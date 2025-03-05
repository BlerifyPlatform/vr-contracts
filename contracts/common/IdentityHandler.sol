// SPDX-License-Identifier: APACHE-2.0
pragma solidity 0.8.18;

import "./IIdentityHandler.sol";
import "../utils/EIP712/EIP712.sol";
import "@openzeppelin/contracts/utils/Context.sol";

abstract contract IdentityHandler is IIdentityHandler, Context, EIP712 {
    bytes32 public defaultDelegateType;
    address public defaultDidRegistry;
    mapping(address => address) public didRegistries;
    // identity => delegateType => bool
    mapping(address => mapping(bytes32 => bool)) public didDelegateTypes;
    mapping(address => mapping(bytes32 => bool)) public nonces;
    bytes32 private constant ADD_DID_REGISTRY_TYPEHASH =
        keccak256(
            "AddDidRegistry(address didRegistryAddress,bytes32 nonce,uint256 intentExpiration)"
        );

    bytes32 private constant REMOVE_DID_REGISTRY_TYPEHASH =
        keccak256("RemoveDidRegistry(bytes32 nonce,uint256 intentExpiration)");

    bytes32 private constant ADD_DELETEGATE_TYPE_TYPEHASH =
        keccak256(
            "AddDelegateType(bytes32 delegateType,bytes32 nonce,uint256 intentExpiration)"
        );

    bytes32 private constant REMOVE_DELETEGATE_TYPE_TYPEHASH =
        keccak256(
            "RemoveDelegateType(bytes32 delegateType,bytes32 nonce,uint256 intentExpiration)"
        );

    constructor(
        address didRegistry,
        bytes32 delegateType,
        string memory name,
        string memory version
    ) EIP712(name, version) {
        // version is expected to be updated if new version is released
        defaultDidRegistry = didRegistry;
        defaultDelegateType = delegateType;
    }

    function _getDefaultDidRegistry() internal view returns (address) {
        return defaultDidRegistry;
    }

    function _getDefaultDelegateType() internal view returns (bytes32) {
        return defaultDelegateType;
    }

    function checkControllerSignature(
        address didRegistry,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS,
        bytes32 hash
    ) internal view returns (address) {
        address signer = ecrecover(hash, sigV, sigR, sigS);
        _validateController(didRegistry, signer, identity);
        return signer;
    }

    function checkDelegateSignature(
        address didRegistry,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS,
        bytes32 hash,
        bytes32 delegateType
    ) internal view returns (address) {
        address delegate = ecrecover(hash, sigV, sigR, sigS);
        _validateDelegate(didRegistry, identity, delegateType, delegate);
        return delegate;
    }

    function getDidRegistry(address identity) public view returns (address) {
        address registryAddress = didRegistries[identity];
        if (registryAddress == address(0)) {
            return defaultDidRegistry;
        }
        return registryAddress;
    }

    function addDidRegistry(address didRegistryAddress) external {
        _addDidRegistry(didRegistryAddress, _msgSender());
    }

    function _addDidRegistry(
        address didRegistryAddress,
        address actor
    ) internal {
        // @todo add extcodesize and function selector verification
        require(
            didRegistryAddress != address(0) &&
                didRegistries[actor] == address(0),
            "IP"
        );
        didRegistries[actor] = didRegistryAddress;
        emit DidRegistryChange(actor, didRegistryAddress, true);
    }

    function addDidRegistrySigned(
        address didRegistryAddress,
        bytes32 nonce,
        uint256 intentExpiration,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(
            ADD_DID_REGISTRY_TYPEHASH,
            didRegistryAddress,
            nonce,
            intentExpiration
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address actor = ecrecover(completeHash, sigV, sigR, sigS);
        _validateAndSetNonce(actor, nonce, intentExpiration);
        _addDidRegistry(didRegistryAddress, actor);
    }

    function _validateAndSetNonce(
        address actor,
        bytes32 nonce,
        uint256 intentExpiration
    ) internal {
        require(intentExpiration >= block.timestamp, "TIE");
        require(!nonces[actor][nonce], "NAR");
        nonces[actor][nonce] = true;
    }

    function removeDidRegistry() external {
        _removeDidRegistry(_msgSender());
    }

    function _removeDidRegistry(address actor) internal {
        // @todo add extcodesize and function selector verification
        address didRegistryAddress = didRegistries[actor];
        require(didRegistries[actor] != address(0), "CDNS");
        didRegistries[actor] = address(0);
        emit DidRegistryChange(actor, didRegistryAddress, false);
    }

    function removeDidRegistrySigned(
        bytes32 nonce,
        uint256 intentExpiration,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(
            REMOVE_DID_REGISTRY_TYPEHASH,
            nonce,
            intentExpiration
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address actor = ecrecover(completeHash, sigV, sigR, sigS);
        _validateAndSetNonce(actor, nonce, intentExpiration);
        _removeDidRegistry(actor);
    }

    function _validateDelegate(
        address didRegistry,
        address identity,
        bytes32 delegateType,
        address delegate
    ) internal view {
        // call didRegistry by passing the sender and the identity
        (bool success, bytes memory data) = didRegistry.staticcall(
            abi.encodeWithSignature(
                "validDelegate(address,bytes32,address)",
                identity,
                delegateType,
                delegate
            )
        );
        require(success && abi.decode(data, (bool)), "ID");
    }

    function _validateController(
        address didRegistry,
        address controller,
        address identity
    ) internal view {
        // call didRegistry by passing the sender and the identity
        (bool success, bytes memory data) = didRegistry.staticcall(
            abi.encodeWithSignature("identityController(address)", identity)
        );
        require(success && abi.decode(data, (address)) == controller, "IC");
    }

    function _validateDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        address delegate
    ) internal view {
        // resolve didRegistry to call
        address registryAddress = getDidRegistry(identity);
        require(isValidDelegateType(identity, delegateType), "DTNS");
        _validateDelegate(registryAddress, identity, delegateType, delegate);
    }

    function isValidDelegateType(
        address identity,
        bytes32 delegateType
    ) public view returns (bool) {
        return didDelegateTypes[identity][delegateType];
    }

    function addDelegateType(bytes32 delegateType) external {
        _addDelegateType(delegateType, _msgSender());
    }

    function _addDelegateType(bytes32 delegateType, address by) internal {
        _delegateTypeChange(delegateType, by, true);
    }

    function addDelegateTypeSigned(
        bytes32 delegateType,
        bytes32 nonce,
        uint256 intentExpiration,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(
            ADD_DELETEGATE_TYPE_TYPEHASH,
            delegateType,
            nonce,
            intentExpiration
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address actor = ecrecover(completeHash, sigV, sigR, sigS);
        _validateAndSetNonce(actor, nonce, intentExpiration);
        _addDelegateType(delegateType, actor);
    }

    function removeDelegateType(bytes32 delegateType) external {
        _removeDelegateType(delegateType, _msgSender());
    }

    function _removeDelegateType(bytes32 delegateType, address by) internal {
        _delegateTypeChange(delegateType, by, false);
    }

    function removeDelegateTypeSigned(
        bytes32 delegateType,
        bytes32 nonce,
        uint256 intentExpiration,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(
            REMOVE_DELETEGATE_TYPE_TYPEHASH,
            delegateType,
            nonce,
            intentExpiration
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address actor = ecrecover(completeHash, sigV, sigR, sigS);
        _validateAndSetNonce(actor, nonce, intentExpiration);
        _removeDelegateType(delegateType, actor);
    }

    function _delegateTypeChange(
        bytes32 delegateType,
        address by,
        bool status
    ) private {
        require(didDelegateTypes[_msgSender()][delegateType] != status, "DAA");
        didDelegateTypes[_msgSender()][delegateType] = status;
        emit NewDelegateTypeChange(delegateType, by, status);
    }
}
