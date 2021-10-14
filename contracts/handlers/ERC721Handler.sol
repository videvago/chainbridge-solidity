pragma solidity 0.6.4;

import "../ERC721Safe.sol";
import "./BridgeHandler.sol";

/**
    @title Handles ERC20 deposits and deposit executions.
    @author ChainSafe Systems.
    @notice This contract is intended to be used with the Bridge contract.
 */
contract ERC721Handler is BridgeHandler, ERC721Safe {
    /**
        @notice See {BridgeHandler-constructor}
     */
    constructor(
        address _bridgeAddress,
        bytes32[] memory initialResourceIDs,
        address[] memory initialContractAddresses,
        bytes32[] memory burnableResouceIDs
    ) public BridgeHandler(_bridgeAddress, initialResourceIDs, initialContractAddresses, burnableResouceIDs){}

    /**
        @notice A deposit is initiatied by making a deposit in the Bridge contract.
        @param resourceID the resourceID used for depositing
        @param depositer Address of account making the deposit in the Bridge contract.
        @param data Consists of: {resourceID}, {amount}, {lenRecipientAddress} 
        and {recipientAddress} all padded to 32 bytes.
        @notice Data passed into the function should be constructed as follows:
        tokenId                     uint256     bytes   0 - 32
        recipientAddress length     uint256     bytes  32 - 64
        recipientAddress            bytes       bytes  64 - 96, must be 20
        @dev Depending if the corresponding {tokenAddress} for the parsed {resourceID} is
        marked true in {_burnList}, deposited tokens will be burned, if not, they will be locked.
     */
    function deposit(
        bytes32 resourceID,
        address depositer,
        bytes   calldata data
    ) external override onlyBridge {
        uint256 tokenId = abi.decode(data[:32], (uint256));

        address tokenAddress = _resourceIDToContractAddress[resourceID];
        require(tokenAddress != address(0), "RecourceID not mapped");

        if ((_status[resourceID] & STATUS_BURN_MINT) != 0) {
            burnERC721(tokenAddress, tokenId);
        } else {
            lockERC721(tokenAddress, depositer, address(this), tokenId);
        }
    }

    /**
        @notice Proposal execution should be initiated when a proposal is finalized in the Bridge contract.
        by a relayer on the deposit's destination chain.
        @param resourceID the resourceID used for executing
        @param data Consists of {resourceID}, {amount}, {lenDestinationRecipientAddress},
        and {destinationRecipientAddress} all padded to 32 bytes.
        @notice Data passed into the function should be constructed as follows:
        amount                                 uint256     bytes  0 - 32
        destinationRecipientAddress length     uint256     bytes  32 - 64, must be 20
        destinationRecipientAddress            bytes       bytes  64 - 96
     */
    function executeProposal(bytes32 resourceID, bytes calldata data) external override onlyBridge {
        address tokenAddress = _resourceIDToContractAddress[resourceID];
        require(tokenAddress != address(0), "RecourceID not mapped");

        (uint256 tokenId, uint256 recipientLength, address recipient) = abi.decode(data, (uint256, uint256, address));
        require(recipientLength == 20, 'Invalid address length');

        if ((_status[resourceID] & STATUS_BURN_MINT) != 0) {
            bytes memory payload = bytes(data[84:]);
            mintERC721(tokenAddress, recipient, tokenId, payload);
        } else {
            releaseERC721(tokenAddress, address(this), recipient, tokenId);
        }
    }

    /**
        @notice Used to manually release ERC20 tokens from ERC20Safe.
        @param resourceID the resourceID used for releasing
        @param data Data is abi encoded {amount, recipientLength, recipient}
     */
    function release(bytes32 resourceID, bytes calldata data) external override onlyBridge {
        address tokenAddress = _resourceIDToContractAddress[resourceID];
        require(tokenAddress != address(0), "RecourceID not mapped");

        (uint256 tokenId, uint256 recipientLength, address recipient) = abi.decode(data, (uint256, uint256, address));
        require(recipientLength == 20, 'Invalid address length');

        releaseERC721(tokenAddress, address(this), recipient, tokenId);
    }
}
