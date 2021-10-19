pragma solidity 0.6.4;

import "../interfaces/IBridgeHandler.sol";

/**
    @title Function used across handler contracts.
    @author ChainSafe Systems.
    @notice This contract is intended to be used with the Bridge contract.
 */
abstract contract BridgeHandler is IBridgeHandler {
    address public _bridgeAddress;

    // resourceID => token contract address
    mapping (bytes32 => address) public _resourceIDToContractAddress;

    // token contract address => resourceID
    mapping (address => bytes32) public _contractAddressToResourceID;

    // tokens should be minted / burned
    uint256 public constant STATUS_BURN_MINT = 1;

    // token contract address => status
    mapping (bytes32 => uint256) public _status;

    modifier onlyBridge() {
        require(msg.sender == _bridgeAddress, "Bridge only");
        _;
    }


    /**
        @param bridgeAddress Contract address of previously deployed Bridge.
        @param initialResourceIDs Resource IDs are used to identify a specific contract address.
        These are the Resource IDs this contract will initially support.
        @param initialContractAddresses These are the addresses the {initialResourceIDs} will point to, and are the contracts that will be
        called to perform various deposit calls.
        @param burnableResouceIDs These reesourceIDs will be set as burnable and when {deposit} is called, the deposited token will be burned.
        When {executeProposal} is called, new tokens will be minted.
        @dev {initialResourceIDs} and {initialContractAddresses} must have the same length (one resourceID for every address).
        Also, these arrays must be ordered in the way that {initialResourceIDs}[0] is the intended resourceID for {initialContractAddresses}[0].
     */
    function initialize(
        address bridgeAddress,
        bytes32[] memory initialResourceIDs,
        address[] memory initialContractAddresses,
        bytes32[] memory burnableResouceIDs
    ) public {
        require(_bridgeAddress == address(0), 'Already initialized');

        _bridgeAddress = bridgeAddress;

        require(initialResourceIDs.length == initialContractAddresses.length, "Length mismatch");

        for (uint256 i = 0; i < initialResourceIDs.length; i++) {
            _setResource(initialResourceIDs[i], initialContractAddresses[i]);
        }

        for (uint256 i = 0; i < burnableResouceIDs.length; i++) {
            _setBurnable(burnableResouceIDs[i]);
        }
    }

    /**
        @notice see {IBridgeHandler-setResource}
     */
    function setResource(bytes32 resourceID, address contractAddress) external override onlyBridge {
        _setResource(resourceID, contractAddress);
    }

    /**
        @notice see {IBridgeHandler-setBurnable}
     */
    function setBurnable(bytes32 resourceID) external override onlyBridge{
        _setBurnable(resourceID);
    }

    function _setResource(bytes32 resourceID, address contractAddress) internal {
        _resourceIDToContractAddress[resourceID] = contractAddress;
        _contractAddressToResourceID[contractAddress] = resourceID;

       delete _status[resourceID];
    }

    function _setBurnable(bytes32 resourceID) internal {
        _status[resourceID] |= STATUS_BURN_MINT;
    }
}
