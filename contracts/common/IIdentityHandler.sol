// SPDX-License-Identifier: APACHE-2.0

pragma solidity 0.8.18;

/**
 * @dev This interface defines the core methods that allows any contract to connect to a ERC-1056 compiant contract and
 * verify whether a delegate is valid
 */
interface IIdentityHandler {
    /**
     * @dev Every entity is able to just add one didRegistry (address) or update it.
     * Main identity is the only that that can add a didRegistry only valid for him
     * By adding a didRegistry tied to a entity the verification about delegates goes always through that contract
     */
    function changeDidRegistry(address didRegistryAddress) external;

    /**
     * @dev removes the custom didRegistry if exists otherwise reverts
     */
    function removeDidRegistry() external;

    /**
     * @dev Returns the didRegistry and delegateType set for an identity
     */
    function getDidRegistry(
        address identity
    ) external view returns (DidRegistryDetails memory didRegistryDetails);

    /**
     * @dev Associates a delegate type with an entity. The intention is to allow just that kind of delegates to perform actions
     * on behalf of the entity. More than one delegate type can be associated to a given entity
     */
    function addDelegateType(bytes32 delegateType) external;

    /**
     * @dev Removes a delegate type associated to an entity.
     */
    function removeDelegateType(bytes32 delegateType) external;

    /**
     * @dev Validates whether a delegate type is valid for a given entity
     */
    function isValidDelegateType(
        address identity,
        bytes32 delegateType
    ) external view returns (bool);

    /**
    * @dev if status true, the added delegate type will be valid for just all delegates under "by" (which represents an identifier for the
    main identity)
     */
    event NewDelegateTypeChange(
        bytes32 indexed delegateType,
        address indexed by,
        bool status
    );

    /**
     * @dev if status true, the added didRegistry is valid for the specified "by" entity, otherwise it will be no longer valid.
     */
    event DidRegistryChange(
        address indexed by,
        address indexed oldDidRegistry,
        address indexed newDidRegistry
    );

    /**
     * @dev Keeps track of a custo DID registry, in case an actor wants to use a different one rather than the default DID Registry
     * @param didRegistry The custom Did registry
     * @param nonce An incrementing value that follows every state change
     */
    struct DidRegistryDetails {
        address didRegistry;
        uint64 nonce;
    }

    /**
     * @dev A struct to keep track of custom delegate types
     * @param status Indicating whether a particuar delegate type is set or not for a given actor
     * @param nonce An incrementing value that follows every state change
     */
    struct DelegateTypeState {
        bool status;
        uint64 nonce;
    }
}
