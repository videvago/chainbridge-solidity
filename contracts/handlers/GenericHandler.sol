pragma solidity 0.6.4;

import "./BridgeHandler.sol";

/**
    @title Handles generic messaging.
    @author ChainSafe Systems.
    @notice This contract is intended to be used with the Bridge contract.
 */
contract GenericHandler is BridgeHandler {
    /**
        @notice A deposit is initiatied by making a deposit in the Bridge contract.
        @param resourceID the resourceID used for depositing
     */
    function deposit(
        bytes32 resourceID,
        address/* depositer*/,
        bytes calldata/* data*/
    ) external override onlyBridge {
        address tokenAddress = _resourceIDToContractAddress[resourceID];
        require(tokenAddress != address(0), "RecourceID not mapped");
    }

    /**
        @notice Execute a proposal message executed from a user
        @param resourceID the resourceID used for executing
     */
    function executeProposal(bytes32 resourceID, bytes calldata/* data*/) external override onlyBridge {
        address tokenAddress = _resourceIDToContractAddress[resourceID];
        require(tokenAddress != address(0), "RecourceID not mapped");
    }

    /**
        @notice Used to manually release ERC20 tokens from ERC20Safe.
        @param resourceID the resourceID used for releasing
     */
    function release(bytes32 resourceID, bytes calldata/* data*/) external override onlyBridge {
        address tokenAddress = _resourceIDToContractAddress[resourceID];
        require(tokenAddress != address(0), "RecourceID not mapped");
    }
}
