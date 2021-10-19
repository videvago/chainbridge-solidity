pragma solidity 0.6.4;
pragma experimental ABIEncoderV2;

import "./utils/AccessControl.sol";
import "./utils/Pausable.sol";
import "./utils/SafeMath.sol";
import "./interfaces/IBridgeHandler.sol";
import "./interfaces/IBridge.sol";

struct Signature {
  bytes32 v;
  bytes32 r;
  bytes32 s;
}

/**
    @title Facilitates deposits, creation and votiing of deposit proposals, and deposit executions.
    @author ChainSafe Systems.
 */
contract Bridge is Pausable, AccessControl, SafeMath {

    uint8 public _chainID;
    uint256 public _relayerThreshold;
    uint256 public _fee;
    uint256 public _expiry;

    enum ProposalStatus {Inactive, Active, Passed, Executed, Cancelled}

    // Limit relayers number because proposal can fit only so much votes
    uint256 constant public MAX_RELAYERS = 200;

    struct Proposal {
        ProposalStatus _status;
        uint200 _yesVotes;      // bitmap, 200 maximum votes
        uint8   _yesVotesTotal;
        uint40  _proposedBlock; // 1099511627775 maximum block
    }

    // destinationChainID => number of deposits
    mapping(uint8 => uint64) public _depositCounts;
    // resourceID => handler address
    mapping(bytes32 => address) public _resourceIDToHandlerAddress;
    // depositKey => Proposal
    mapping(bytes32 => Proposal) public _proposals;
    // depositKey => ProposalSignatures
    mapping(bytes32 => Signature[]) private _signatures;
    // depositKey => msgExecuted
    mapping(bytes32 => uint256) private _executedMessages;

    event RelayerThresholdChanged(uint indexed newThreshold);
    event RelayerAdded(address indexed relayer);
    event RelayerRemoved(address indexed relayer);
    event Deposit(
        address indexed from,
	bytes32 indexed executor,
        bytes32 depositKey,
        uint8 destinationChainID,
        uint64 depositNonce,
        bytes32 resourceID,
	bytes data
    );
    event ProposalEvent(
	bytes32 indexed depositKey,
        ProposalStatus  status
    );

    event ProposalVote(
        bytes32 indexed depositKey,
        ProposalStatus status
    );

    event Execute(
        bytes32 indexed executor,
        bytes32 indexed depositKey,
        uint8   originChainID,
        uint8   destinationChainID,
        bytes   data
    );

    event Executed(
        address indexed executor,
        bytes32 indexed depositKey
    );

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    modifier onlyAdmin() {
        _onlyAdmin();
        _;
    }

    modifier onlyAdminOrRelayer() {
        _onlyAdminOrRelayer();
        _;
    }

    modifier onlyRelayers() {
        _onlyRelayers();
        _;
    }

    function _onlyAdminOrRelayer() private view {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || hasRole(RELAYER_ROLE, msg.sender),
            "Only admin or relayer");
    }

    function _onlyAdmin() private view {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Only admin");
    }

    function _onlyRelayers() private view {
        require(hasRole(RELAYER_ROLE, msg.sender), "Only relayer");
    }

    /**
        @notice Initializes Bridge, creates and grants {msg.sender} the admin role,
        creates and grants {initialRelayers} the relayer role.
        @param chainID ID of chain the Bridge contract exists on.
        @param initialRelayers Addresses that should be initially granted the relayer role.
        @param initialRelayerThreshold Number of votes needed for a deposit proposal to be considered passed.
     */
    constructor (uint8 chainID, address[] memory initialRelayers, uint initialRelayerThreshold, uint256 fee, uint256 expiry) public {
        _chainID = chainID;
        _relayerThreshold = initialRelayerThreshold;
        _fee = fee;
        _expiry = expiry;

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setRoleAdmin(RELAYER_ROLE, DEFAULT_ADMIN_ROLE);

        for (uint i; i < initialRelayers.length; i++) {
            grantRole(RELAYER_ROLE, initialRelayers[i]);
        }
    }

    /**
        @notice Returns true if {relayer} has the relayer role.
        @param relayer Address to check.
     */
    function isRelayer(address relayer) external view returns (bool) {
        return hasRole(RELAYER_ROLE, relayer);
    }

    /**
        @notice Returns true if {relayer} has voted on {destNonce} {dataHash} proposal.
        @param depositKey see {_getDepositKey}.
        @param relayer Address to check.
     */
    function _hasVotedOnProposal(bytes32 depositKey, address relayer) public view returns(bool) {
        return _hasVoted(_proposals[depositKey], relayer);
    }

    /**
        @notice Removes admin role from {msg.sender} and grants it to {newAdmin}.
        @notice Only callable by an address that currently has the admin role.
        @param newAdmin Address that admin role will be granted to.
     */
    function renounceAdmin(address newAdmin) external onlyAdmin {
        grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        renounceRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
        @notice Pauses deposits, proposal creation and voting, and deposit executions.
        @notice Only callable by an address that currently has the admin role.
     */
    function adminPauseTransfers() external onlyAdmin {
        _pause();
    }

    /**
        @notice Unpauses deposits, proposal creation and voting, and deposit executions.
        @notice Only callable by an address that currently has the admin role.
     */
    function adminUnpauseTransfers() external onlyAdmin {
        _unpause();
    }

    /**
        @notice Modifies the number of votes required for a proposal to be considered passed.
        @notice Only callable by an address that currently has the admin role.
        @param newThreshold Value {_relayerThreshold} will be changed to.
        @notice Emits {RelayerThresholdChanged} event.
     */
    function adminChangeRelayerThreshold(uint newThreshold) external onlyAdmin {
        _relayerThreshold = newThreshold;
        emit RelayerThresholdChanged(newThreshold);
    }

    /**
        @notice Grants {relayerAddress} the relayer role.
        @notice Only callable by an address that currently has the admin role.
        @notice Admin role is checked in grantRole
        @param relayerAddress Address of relayer to be added.
        @notice Emits {RelayerAdded} event.
     */
    function adminAddRelayer(address relayerAddress) external {
	require(getRoleMemberCount(RELAYER_ROLE) < MAX_RELAYERS, 'Max relayers reached');
        require(!hasRole(RELAYER_ROLE, relayerAddress), "Already registered!");
        grantRole(RELAYER_ROLE, relayerAddress);
        emit RelayerAdded(relayerAddress);
    }

    /**
        @notice Removes relayer role for {relayerAddress} and decreases {_totalRelayer} count.
        @notice Only callable by an address that currently has the admin role.
        @notice Admin role is checked in revokeRole
        @param relayerAddress Address of relayer to be removed.
        @notice Emits {RelayerRemoved} event.
     */
    function adminRemoveRelayer(address relayerAddress) external {
        require(hasRole(RELAYER_ROLE, relayerAddress), "Not registered!");
        revokeRole(RELAYER_ROLE, relayerAddress);
        emit RelayerRemoved(relayerAddress);
    }

    /**
        @notice Maps the {handlerAddress} to {resourceID} in {_resourceIDToHandlerAddress}.
        @notice Only callable by an address that currently has the admin role.
        @param handlerAddress Address of handler resource will be set for.

        @param resourceID ResourceID to be used when making deposits.
        @param tokenAddress Address of contract to be called when a deposit is made and a deposited is executed.
     */
    function adminSetResource(address handlerAddress, bytes32 resourceID, address tokenAddress) external onlyAdmin {
        _resourceIDToHandlerAddress[resourceID] = handlerAddress;
        IBridgeHandler(handlerAddress).setResource(resourceID, tokenAddress);
    }

    /**
        @notice Sets a resource as burnable for handler contracts that use the IERCHandler interface.
        @notice Only callable by an address that currently has the admin role.
        @param resourceID ResourceID to be called to withdraw funds from
     */
    function adminSetBurnable(bytes32 resourceID) external onlyAdmin {
        address handler = _resourceIDToHandlerAddress[resourceID];
        require(handler != address(0), 'Invalid resourceID');
        IBridgeHandler(handler).setBurnable(resourceID);
    }


    /**
        @notice Returns a depositKey made of deposit data.
        @param destinationChainID ID of chain deposit will be bridged to.
        @param resourceID ResourceID used to find address of handler to be used for deposit.
        @param data Additional data to be passed to specified handler.
        @return Deposit Key:
     */
    function getDepositKey(uint8 originChainID, uint8 destinationChainID, uint64 depositNonce, bytes32 resourceID, bytes calldata data) external pure returns (bytes32) {
        return _getDepositKey(originChainID, destinationChainID, depositNonce, resourceID, data);
    }

    /**
        @notice Returns a proposal.
        @param depositKey see {_getDepositKey}.
        @return Proposal which consists of:
        - _status Current status of proposal.
        - _yesVotes Number of votes in favor of proposal.
        - _noVotes Number of votes against proposal.
        - _proposedBlock Block when proposal started
     */
    function getProposal(bytes32 depositKey) external view returns (Proposal memory) {
        return _proposals[depositKey];
    }


    /**
        @notice Returns message execution state
        @param depositKeys Array of depositKeys the execution state to be queried
	@return states Array of uint256 where != 0 is executed state
     */
    function getMessageExecutionState(bytes32[] calldata depositKeys) external view returns (uint256[] memory states) {
        states = new uint256[](depositKeys.length);
        for (uint i = 0; i < depositKeys.length; ++i) {
            states[i] = _executedMessages[depositKeys[i]];
        }
    }

    /**
        @notice Changes deposit fee.
        @notice Only callable by admin.
        @param newFee Value {_fee} will be updated to.
     */
    function adminChangeFee(uint newFee) external onlyAdmin {
        require(_fee != newFee, "Current fee is equal to new fee");
        _fee = newFee;
    }

    /**
        @notice Used to manually release funds from safes.
        @param resourceID ResourceID to be called to withdraw funds from
        @param data Handler specific release data.
     */
    function adminRelease(
        bytes32 resourceID,
	bytes calldata data
    ) external onlyAdmin {
        address handler = _resourceIDToHandlerAddress[resourceID];
        require(handler != address(0), 'Invalid resourceID');
	IBridgeHandler(handler).release(resourceID, data);
    }

    /**
        @notice Initiates a transfer using a specified handler contract.
        @notice Only callable when Bridge is not paused.
        @param data {resourceId:32}{destinationChain:32}{executorLength:32}{executor:*32}.
        @notice Emits {Deposit} event.
     */
    function deposit(bytes32 resourceID, uint8 destinationChainID, bytes calldata executor, bytes calldata data) external payable whenNotPaused {
        require(msg.value == _fee, "Incorrect fee supplied");

        bytes memory executorPadded = bytes(executor);
        if (executorPadded.length & 31 != 0) {
            executorPadded = abi.encodePacked(new bytes(32 - (executor.length & 31)), executorPadded);
        }

        uint64 depositNonce = ++_depositCounts[destinationChainID];

        {
          address handler = _resourceIDToHandlerAddress[resourceID];
          require(handler != address(0), "ResourceID not mapped");

          IBridgeHandler(handler).deposit(resourceID, msg.sender, data);
        }


        bytes32 depositKey = _getDepositKey(
          _chainID,
          destinationChainID,
          depositNonce,
          resourceID,
          data);

        bytes memory enrichedData = abi.encodePacked(
          depositKey,
          resourceID,
          uint256(_chainID),
          uint256(destinationChainID),
          executor.length,
          executorPadded,
          data);

        emit Deposit(
            msg.sender,
            abi.decode(executorPadded, (bytes32)),
            depositKey,
            destinationChainID,
            depositNonce,
            resourceID,
            enrichedData
        );
    }

    /**
        @notice When called, {msg.sender} will be marked as voting in favor of proposal.
        @notice Only callable by relayers when Bridge is not paused.
        @param depositKey Key generated when deposit was made.
        @notice Proposal must not have already been passed or executed.
        @notice {msg.sender} must not have already voted on proposal.
        @notice Emits {ProposalEvent} event with status indicating the proposal status.
        @notice Emits {ProposalVote} event.
     */
    function voteProposal(bytes32 depositKey, bytes32 v, bytes32 r, bytes32 s) external onlyRelayers whenNotPaused {
	Proposal memory proposal = _proposals[depositKey];

        require(proposal._status <= ProposalStatus.Active, "Proposal already processed");
        require(!_hasVoted(proposal, msg.sender), "Already voted");

        if (proposal._status == ProposalStatus.Inactive) {
            proposal = Proposal({
                _status : ProposalStatus.Active,
                _yesVotes : 0,
                _yesVotesTotal : 0,
                _proposedBlock : uint40(block.number) // Overflow is desired.
            });

            emit ProposalEvent(depositKey, ProposalStatus.Active);
        } else if (uint40(sub(block.number, proposal._proposedBlock)) > _expiry) {
            // if the number of blocks that has passed since this proposal was
            // submitted exceeds the expiry threshold set, cancel the proposal
            proposal._status = ProposalStatus.Cancelled;

            emit ProposalEvent(depositKey, ProposalStatus.Cancelled);
        }

        if (proposal._status != ProposalStatus.Cancelled) {
            proposal._yesVotes = uint200(proposal._yesVotes | _relayerBit(msg.sender));
            proposal._yesVotesTotal++; // TODO: check if bit counting is cheaper.
            _signatures[depositKey].push(Signature(v,r,s));

            emit ProposalVote(depositKey, proposal._status);

            // Finalize if _relayerThreshold has been reached
            if (proposal._yesVotesTotal >= _relayerThreshold) {
                proposal._status = ProposalStatus.Passed;

                emit ProposalEvent(depositKey, ProposalStatus.Passed);
            }
        }
        _proposals[depositKey] = proposal;
    }

    /**
        @notice Cancel a proposal.
        @notice Only callable by relayers and admin.
        @param depositKey Key generated when deposit was made.
        @notice Proposal must be past expiry threshold.
        @notice Emits {ProposalEvent} event with status {Cancelled}.
     */
    function cancelProposal(bytes32 depositKey) public onlyAdminOrRelayer {
        Proposal storage proposal = _proposals[depositKey];

        require(proposal._status != ProposalStatus.Cancelled, "Proposal already cancelled");
        require(sub(block.number, proposal._proposedBlock) > _expiry, "Proposal not at expiry threshold");

        proposal._status = ProposalStatus.Cancelled;
        emit ProposalEvent(depositKey, ProposalStatus.Cancelled);
    }

    /**
        @notice Executes a deposit proposal by emitting an {Execute} event.
        @notice Only callable by relayers when Bridge is not paused.
        @param data {dKey:32}{rId:32}{srcId:32}{destId:32}{execLen:32}{executor:32*x}.
        @notice Proposal must have Passed status.
        @notice Emits {ProposalEvent} event with status {Executed}.
     */
    function executeProposal(
        bytes calldata data) external onlyRelayers whenNotPaused 
    {
        bytes32 depositKey = abi.decode(data[:32], (bytes32));
        {
            Proposal storage proposal = _proposals[depositKey];

            require(proposal._status == ProposalStatus.Passed, "Proposal not passed");

            proposal._status = ProposalStatus.Executed;

            emit ProposalEvent(depositKey, proposal._status);
        }

	// Build signatures stack
        bytes memory sigBytes = new bytes(0);
        {
            Signature[] storage signatures = _signatures[depositKey];
            for (uint i = 0; i < signatures.length; ++i) {
                sigBytes = abi.encodePacked(sigBytes, signatures[i].v, signatures[i].r, signatures[i].s);
            }
            // Cleanup
            delete _signatures[depositKey];
        }

        emit Execute(
            abi.decode(data[160:192], (bytes32)), // executor
            depositKey,
            uint8(abi.decode(data[64:96], (uint256))), // originChainId
            uint8(abi.decode(data[96:128], (uint256))), // destinationChainId
            abi.encodePacked(sigBytes.length / 96, sigBytes, data)
        );
    }


    /**
        @notice Executes a message emitted from executeProposal.
        @notice Only callable when Bridge is not paused.
        @param data Signed data emitted in Execute event
        {numSig:32}{sigs:96}{dkey:32}{rId:32}{srcId:32}{destId:32}{execLen:32}{executor:32}{handlerData}
        @param adminNoThreshold allow admin to execute without threshold
        This could be required for pending messages if threshold is changed
        @notice only executor is allowed to execute
        @notice chainId must match this chainId.
        @notice there has to be a valid handler for the given resouceId.
        @notice Emits {MessageExecuted} event.
     */
    function executeMessage(bytes calldata data, uint256 adminNoThreshold) external whenNotPaused {
        uint256 dataOffset = 32;
        {
	    // Number of signatures
            uint256 numSignatures = abi.decode(data[:32], (uint256));
            if (adminNoThreshold > 0)
                _onlyAdmin();
            else
                require(numSignatures >= _relayerThreshold, 'Not enough signers');

            // Verify signatures
            bytes32 dataHash = keccak256(bytes(data[32 + numSignatures * 96:]));
            uint256 signerMask = 0;
            for (uint256 i = 0; i < numSignatures; ++i) {
                (uint8 v, bytes32 r, bytes32 s) = abi.decode(data[dataOffset:dataOffset+96],(uint8, bytes32, bytes32));
                if (v < 27) v += 27;
                require(v == 27 || v == 28, 'Invalid sigature');

                address relayer = ecrecover(dataHash, v, r, s);
                require(hasRole(RELAYER_ROLE, relayer), 'Not a relayer');
                uint256 oldSignerMask = signerMask;
                require(oldSignerMask != (signerMask |= _relayerBit(relayer)), 'Already signed');

                dataOffset += 96;
            }
        }

        {
            bytes32 depositKey = abi.decode(data[dataOffset:dataOffset + 32], (bytes32));
            require(_executedMessages[depositKey] == 0, 'Already executed');
            // Mark this message as executed.
            _executedMessages[depositKey] = 1;

            emit Executed(msg.sender, depositKey);
        }
        {
            uint256 destinationChainID = abi.decode(data[dataOffset + 96:dataOffset + 128], (uint256));
            require(destinationChainID == uint256(_chainID));

            uint256 executorLength = abi.decode(data[dataOffset + 128:dataOffset + 160], (uint256));
            require(executorLength == 20, 'Invalid address length');
            address executor = abi.decode(data[dataOffset + 160:dataOffset + 192], (address));
            require(executor == msg.sender, 'Only executor');
        }

        bytes32 resourceID = abi.decode(data[dataOffset + 32:dataOffset + 64], (bytes32));
        address handler = _resourceIDToHandlerAddress[resourceID];
        require(handler != address(0), "ResourceID not mapped");

        IBridgeHandler(handler).executeProposal(resourceID, bytes(data[dataOffset + 192:]));
    }

    /**
        @notice Transfers eth in the contract to the specified addresses. The parameters addrs and amounts are mapped 1-1.
        This means that the address at index 0 for addrs will receive the amount (in WEI) from amounts at index 0.
        @param addrs Array of addresses to transfer {amounts} to.
        @param amounts Array of amonuts to transfer to {addrs}.
     */
    function transferFunds(address payable[] calldata addrs, uint[] calldata amounts) external onlyAdmin {
        for (uint i = 0; i < addrs.length; i++) {
            addrs[i].transfer(amounts[i]);
        }
    }

    /**
        @notice Create trackable depositKey
     */
    function _getDepositKey(
      uint8 originChainID,
      uint8 destinationChainID,
      uint64 depositNonce,
      bytes32 resourceID,
      bytes memory data) private pure returns (bytes32)
    {
        return keccak256(abi.encodePacked(
          originChainID,
          destinationChainID,
          depositNonce,
          resourceID,
          data
        ));
    }


    /**
        @notice Get bitmask bit of the current relayer
     */
    function _relayerBit(address relayer) private view returns(uint256) {
        return uint256(1) << sub(AccessControl.getRoleMemberIndex(RELAYER_ROLE, relayer), 1);
    }

    /**
        @notice Check with help of bitmask if relayer has voted
     */
    function _hasVoted(Proposal memory proposal, address relayer) private view returns(bool) {
        return (_relayerBit(relayer) & uint(proposal._yesVotes)) > 0;
    }
}
