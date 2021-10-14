pragma solidity 0.6.4;

/**
    @title Interface for handler contracts that support deposits and deposit executions.
    @author ChainSafe Systems.
    @author videvago GmbH
 */
interface IBridgeHandler {
    /**
        @notice It is intended that deposit are made using the Bridge contract.
        @param resourceID ResourceID used to find address of contract.
        @param depositer Address of account making the deposit in the Bridge contract.
        @param data Consists of additional data needed for a specific deposit.
     */
    function deposit(bytes32 resourceID, address depositer, bytes calldata data) external;

    /**
        @notice It is intended that proposals are executed by the Bridge contract.
        @param data Consists of additional data needed for a specific deposit execution.
     */
    function executeProposal(bytes32 resourceID, bytes calldata data) external;

    /**
        @notice Registers a new contract address for a resourceID
        @notice Resets burnable
        @param resourceID ResourceID to be used when making deposits.
        @param contractAddress Address of contract to be called when a deposit is made and a deposited is executed.
     */
    function setResource(bytes32 resourceID, address contractAddress) external;

    /**
        @notice Enable mint / burn
        @param resourceID ResourceID used to set burnable status.
     */
    function setBurnable(bytes32 resourceID) external;

    /**
        @notice Used to manually release funds.
        @param resourceID ResourceID used to release funds.
        @param data Handler specific data for releasing funds
     */
    function release(bytes32 resourceID, bytes calldata data) external;
}
