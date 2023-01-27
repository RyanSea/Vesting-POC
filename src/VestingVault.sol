// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { SafeTransferLib, ERC20 } from "solmate/utils/SafeTransferLib.sol";

import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";

/// @notice a simple vault for vesting tokens
contract VestingVault {

    /*//////////////////////////////////////////////////////////////
                             INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    using SafeTransferLib for ERC20;
    using ECDSA for bytes32;

    /// @notice project name
    string public name;

    /// @notice underlying token contract
    ERC20 public asset;

    /// @notice leadership address
    address public mgmt;

    constructor(
        string memory _name, 
        address _asset,
        address _mgmt
    ) {
        name = _name;
        asset = ERC20(_asset);
        mgmt = _mgmt;
    }

    /*//////////////////////////////////////////////////////////////
                                 PARAMS
    //////////////////////////////////////////////////////////////*/

    /// @notice unit for time-based vesting
    /// @param amount to vest
    /// @param time to vest at
    struct Tranche {
        uint256 amount;
        uint256 time;
    }

    /// @notice unit for milestone-based vesting
    /// @param amount to vest
    /// @param milestone to vest on | @dev hash of encoded string
    struct Milestone {
        uint256 amount;
        bytes32 milestone;
    }

    /// note: could implement something like https://www.superfluid.finance/ for token stream vesting / payroll
    /// struct Stream { ... }

    /// @notice signature struct
    /// @param signature of team mate
    /// @param nonce of signature, to prevent unauthorized re-use
    struct Signature {
        bytes signature;
        uint256 nonce;
    }

    /// @notice asserts sender is mgmt
    modifier onlyMgmt {
        require(msg.sender == mgmt, "NOT_LEADER");
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/
    
    event NewVestingSchedule(address indexed teamMember, Tranche[] vestingPeriods);

    event NewMilestones(address indexed teamMember, Milestone[] milestones);

    event CompletedMilestones(address indexed teamMember, bytes32[] finishedMilestones);

    event VestedFromSchedule(address indexed teamMember, uint256 vested);

    event VestedFromMilestones(address indexed teamMember, uint256 vested);

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice team member => encoded Tranche[]
    mapping(address => bytes) internal vestingSchedule;

    /// @notice team member => encoded Milestone[]
    mapping(address => bytes) internal vestingMilestones;

    /// @notice team member => milestone => whether or not they've completed it
    mapping(address => mapping(bytes32 => bool)) public completedMilstones;

    /// @notice team member => signature nonce => whether it's been used
    mapping(address => mapping(uint256 => bool)) public nonceUsed;

    /*//////////////////////////////////////////////////////////////
                            LEADERSHIP LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice sets vesting schedule for team member
     *
     * @dev team member must sign tranches w/ unused nonce to prevent unauthorized
     *      reuse of signature
     * @dev treasury must approve contract for >=total amount of tokens
     * @dev only callable by leadership
     *
     * @param treasury                      project treasury
     * @param teamMember                    address of team member
     * @param vestingPeriods                Tranche[] of vesting periods
     * @param sig                           Signature struct 
    */
    function setVestingSchedule(
        address treasury,
        address teamMember, 
        Tranche[] calldata vestingPeriods,
        Signature memory sig
    ) external onlyMgmt {
        require(!nonceUsed[teamMember][sig.nonce], "NONCE_USED");

        nonceUsed[teamMember][sig.nonce] = true;

        bytes memory _vestingPeriods = abi.encode(vestingPeriods);

        bytes32 hash = keccak256(bytes.concat(_vestingPeriods,abi.encode(sig.nonce))).toEthSignedMessageHash();

        require(teamMember == hash.recover(sig.signature), "INVALID_SIGNATURE");
    
        uint total;

        uint length = vestingPeriods.length;

        for (uint i; i < length; ) {
            total += vestingPeriods[i].amount;

            unchecked { ++i; }
        }

        asset.safeTransferFrom(treasury, address(this), total);

        vestingSchedule[teamMember] = _vestingPeriods;

        emit NewVestingSchedule(teamMember, vestingPeriods);
    }

    /**
     * @notice sets vesting milestones for team member
     *
     * @dev team member must sign tranches w/ unused nonce to prevent unauthorized
     *      reuse of signature
     * @dev treasury must approve contract for >=total amount of tokens
     * @dev only callable by leadership
     *
     * @param treasury                      project treasury
     * @param teamMember                    address of team member
     * @param milestones                    Milestone[] of milestones
     * @param sig                           Signature struct 
    */
    function setVestingMilestones(
        address treasury,
        address teamMember, 
        Milestone[] calldata milestones,
        Signature memory sig
    ) external onlyMgmt {
        require(!nonceUsed[teamMember][sig.nonce], "NONCE_USED");

        nonceUsed[teamMember][sig.nonce] = true;

        bytes memory _milestones = abi.encode(milestones);

        bytes32 hash = keccak256(bytes.concat(_milestones,abi.encode(sig.nonce))).toEthSignedMessageHash();

        require(teamMember == hash.recover(sig.signature), "INVALID_SIGNATURE");

        uint total;

        uint length = milestones.length;

        for (uint i; i < length; ) {
            total += milestones[i].amount;

            unchecked { ++i; }
        }

        asset.safeTransferFrom(treasury, address(this), total);

        vestingMilestones[teamMember] = _milestones;

        emit NewMilestones(teamMember, milestones);
    }

    /**
     * @notice sets vesting schedule for team member
     *
     * @dev only callable by leadership
     *
     * @param teamMember                    address of team member
     * @param finishedMilestones            array of hashes for encoded milestones
    */
    function updateMilestones(address teamMember, bytes32[] calldata finishedMilestones) external onlyMgmt {
        uint length = finishedMilestones.length;
        for (uint i; i < length; ) {
            completedMilstones[teamMember][finishedMilestones[i]] = true;

            unchecked { ++i; }
        }

        emit CompletedMilestones(teamMember, finishedMilestones);
    }

    /*//////////////////////////////////////////////////////////////
                               TEAM LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice vests from schedule
     *
     * @dev frontend should static call this function to see whether
     *      anything is vest-ready
     *
     * @param receiver                      receiving address for funds
    */
    function vestFromSchedule(address receiver) external returns (bool success) {
        address teamMember = msg.sender;

        Tranche[] memory tranches = abi.decode(vestingSchedule[teamMember],(Tranche[]));

        uint current = block.timestamp;

        uint vested;

        uint total;

        uint length = tranches.length;

        // loop through tranches adding completed tranches to vested
        // & left shifting incompleted tranches total [num of completed] indexes
        for (uint i; i < length; ) {
            if (tranches[i].time >= current) {
                vested += tranches[i].amount;

                unchecked { ++total; }
            } else {
                // total can never be greater than i
                unchecked { tranches[i - total] = tranches[i]; }
            }

            unchecked { ++i; }
        }

        if (total == 0) return false;
        success = true;

        // pop repeated items, due to shifting, from tranches
        assembly { mstore(mload(tranches), sub(mload(tranches), total)) }

        vestingSchedule[teamMember] = abi.encode(tranches);

        asset.safeTransfer(receiver, vested);

        emit VestedFromSchedule(teamMember, vested);
    }

    /**
     * @notice vests from milestones
     *
     * @dev frontend should static call this function to see whether
     *      anything is vest-ready
     *
     * @param receiver                      receiving address for funds
    */
    function vestFromMilestones(address receiver) external returns (bool success) {
        address teamMember = msg.sender;

        Milestone[] memory milestones = abi.decode(vestingMilestones[teamMember],(Milestone[]));

        uint vested;

        uint idx;

        uint length = milestones.length;

        Milestone[] memory remainingMilestones = new Milestone[](length);

        // loop through milestones, adding completed milestones to vested 
        // & pushing incompleted milestones to remainingMilestones
        for (uint i; i < length; ) {
            if (completedMilstones[teamMember][milestones[i].milestone]) {
                vested += milestones[i].amount;
            } else {
                remainingMilestones[idx] = milestones[i];

                unchecked { ++idx; }
            }

            unchecked { ++i; }
        }

        if (idx == 0) return false;
        success = true;

        // remove empty indexes from remainingMilestones
        assembly { mstore(mload(remainingMilestones), sub(mload(remainingMilestones), sub(length, idx))) }

        vestingMilestones[teamMember] = abi.encode(remainingMilestones);

        asset.safeTransfer(receiver, vested);

        emit VestedFromMilestones(teamMember, vested);
    }
    
}
