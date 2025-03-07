// SPDX-License-Identifier: APACHE-2.0
pragma solidity 0.8.18;

import "./IIdentityHandler.sol";
import "../utils/EIP712/EIP712.sol";
import "@openzeppelin/contracts/utils/Context.sol";

abstract contract IdentityHandler is IIdentityHandler, Context, EIP712 {
    bytes32 public defaultDelegateType;
    address public defaultDidRegistry;
    mapping(address => DidRegistryDetails) public didRegistries;
    // identity => delegateType => bool
    mapping(address => mapping(bytes32 => DelegateTypeState))
        public didDelegateTypes;
    bytes32 private constant ADD_DID_REGISTRY_TYPEHASH =
        keccak256("AddDidRegistry(address didRegistryAddress,uint64 nonce)");

    bytes32 private constant REMOVE_DID_REGISTRY_TYPEHASH =
        keccak256("RemoveDidRegistry(uint64 nonce)");

    bytes32 private constant ADD_DELETEGATE_TYPE_TYPEHASH =
        keccak256("AddDelegateType(bytes32 delegateType,uint64 nonce)");

    bytes32 private constant REMOVE_DELETEGATE_TYPE_TYPEHASH =
        keccak256("RemoveDelegateType(bytes32 delegateType,uint64 nonce)");

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

    function getDidRegistry(
        address identity
    ) public view returns (DidRegistryDetails memory didRegistryDetails) {
        didRegistryDetails = didRegistries[identity];
        address registryAddress = didRegistryDetails.didRegistry;
        if (registryAddress == address(0)) {
            didRegistryDetails.didRegistry = defaultDidRegistry;
        }
    }

    function addDidRegistry(address didRegistryAddress) external {
        _addDidRegistry(didRegistryAddress, _msgSender());
    }

    function _addDidRegistryWithNonce(
        address didRegistryAddress,
        address actor,
        uint64 nonce
    ) internal {
        DidRegistryDetails storage details = didRegistries[actor];
        _addDidRegistryWithNonceAndData(
            didRegistryAddress,
            actor,
            nonce,
            details
        );
    }

    function _addDidRegistryWithNonceAndData(
        address didRegistryAddress,
        address actor,
        uint64 nonce,
        DidRegistryDetails storage details
    ) internal {
        // @todo add extcodesize and function selector verification
        _validateNonce(nonce, details.nonce);
        require(
            didRegistryAddress != address(0) &&
                didRegistries[actor].didRegistry != didRegistryAddress,
            "IDR"
        );
        address oldDidRegistry = details.didRegistry;
        details.didRegistry = didRegistryAddress;
        details.nonce++;
        emit DidRegistryChange(actor, oldDidRegistry, didRegistryAddress);
    }

    function _addDidRegistry(
        address didRegistryAddress,
        address actor
    ) internal {
        DidRegistryDetails storage details = didRegistries[actor];
        uint64 nonce = details.nonce;
        _addDidRegistryWithNonceAndData(
            didRegistryAddress,
            actor,
            nonce,
            details
        );
    }

    function addDidRegistrySigned(
        address didRegistryAddress,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(
            ADD_DID_REGISTRY_TYPEHASH,
            didRegistryAddress,
            nonce
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address actor = ecrecover(completeHash, sigV, sigR, sigS);
        _addDidRegistryWithNonce(didRegistryAddress, actor, nonce);
    }

    function removeDidRegistry() external {
        _removeDidRegistry(_msgSender());
    }

    function _removeDidRegistry(address actor) internal {
        // @todo add extcodesize and function selector verification
        DidRegistryDetails storage didRegistryDetails = didRegistries[actor];
        _removeDidRegistryWithNonceAndData(
            actor,
            didRegistryDetails.nonce,
            didRegistryDetails
        );
    }

    function _removeDidRegistryWithNonce(address actor, uint64 nonce) internal {
        // @todo add extcodesize and function selector verification
        DidRegistryDetails storage didRegistryDetails = didRegistries[actor];
        _removeDidRegistryWithNonceAndData(actor, nonce, didRegistryDetails);
    }

    function _removeDidRegistryWithNonceAndData(
        address actor,
        uint64 nonce,
        DidRegistryDetails storage didRegistryDetails
    ) internal {
        // @todo add extcodesize and function selector verification
        _validateNonce(nonce, didRegistryDetails.nonce);
        address didRegistryAddress = didRegistryDetails.didRegistry;
        require(didRegistryAddress != address(0), "CDNS");
        didRegistryDetails.didRegistry = address(0);
        didRegistryDetails.nonce++;
        emit DidRegistryChange(actor, didRegistryAddress, address(0));
    }

    function removeDidRegistrySigned(
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(REMOVE_DID_REGISTRY_TYPEHASH, nonce);
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address actor = ecrecover(completeHash, sigV, sigR, sigS);
        _removeDidRegistryWithNonce(actor, nonce);
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
        address registryAddress = getDidRegistry(identity).didRegistry;
        require(isValidDelegateType(identity, delegateType), "DTNS");
        _validateDelegate(registryAddress, identity, delegateType, delegate);
    }

    function isValidDelegateType(
        address identity,
        bytes32 delegateType
    ) public view returns (bool isValid) {
        isValid = didDelegateTypes[identity][delegateType].status;
    }

    function addDelegateType(bytes32 delegateType) external {
        _addDelegateType(delegateType, _msgSender());
    }

    function _addDelegateType(bytes32 delegateType, address by) internal {
        _delegateTypeChange(delegateType, by, true);
    }

    function addDelegateTypeSigned(
        bytes32 delegateType,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(
            ADD_DELETEGATE_TYPE_TYPEHASH,
            delegateType,
            nonce
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address actor = ecrecover(completeHash, sigV, sigR, sigS);
        _delegateTypeChangeWithNonce(delegateType, actor, true, nonce);
    }

    function removeDelegateType(bytes32 delegateType) external {
        _removeDelegateType(delegateType, _msgSender());
    }

    function _removeDelegateType(bytes32 delegateType, address by) internal {
        _delegateTypeChange(delegateType, by, false);
    }

    function removeDelegateTypeSigned(
        bytes32 delegateType,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(
            REMOVE_DELETEGATE_TYPE_TYPEHASH,
            delegateType,
            nonce
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address actor = ecrecover(completeHash, sigV, sigR, sigS);
        _delegateTypeChangeWithNonce(delegateType, actor, false, nonce);
    }

    function _delegateTypeChange(
        bytes32 delegateType,
        address by,
        bool status
    ) private {
        DelegateTypeState storage _delegateType = didDelegateTypes[by][
            delegateType
        ];
        uint64 nonce = _delegateType.nonce;
        _delegateTypeChangeWithNonceAndData(
            delegateType,
            by,
            status,
            nonce,
            _delegateType
        );
    }

    function _delegateTypeChangeWithNonceAndData(
        bytes32 delegateType,
        address by,
        bool status,
        uint64 nonce,
        DelegateTypeState storage _delegateType
    ) private {
        _validateNonce(nonce, _delegateType.nonce);
        require(_delegateType.status != status, "DAA");
        _delegateType.status = status;
        _delegateType.nonce++;
        emit NewDelegateTypeChange(delegateType, by, status);
    }

    function _delegateTypeChangeWithNonce(
        bytes32 delegateType,
        address by,
        bool status,
        uint64 nonce
    ) internal {
        DelegateTypeState storage _delegateType = didDelegateTypes[by][
            delegateType
        ];
        _delegateTypeChangeWithNonceAndData(
            delegateType,
            by,
            status,
            nonce,
            _delegateType
        );
    }

    function _validateNonce(uint64 nonceValue, uint64 expected) internal pure {
        require(nonceValue == expected, "IN");
    }
}
