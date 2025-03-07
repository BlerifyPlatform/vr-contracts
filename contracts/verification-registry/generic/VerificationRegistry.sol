// SPDX-License-Identifier: APACHE-2.0
pragma solidity 0.8.18;

import "../IVerificationRegistry.sol";

import "../../common/IdentityHandler.sol";
import "@openzeppelin/contracts/utils/Context.sol";

contract VerificationRegistry is IVerificationRegistry, IdentityHandler {
    constructor(
        address didRegistry,
        bytes32 delegateType
    )
        IdentityHandler(
            didRegistry,
            delegateType,
            "VerificationRegistry",
            version
        )
    {}

    string public constant version = "010"; // max value MUST BE 0xffff
    mapping(bytes32 => mapping(address => Detail)) private registers;
    bytes32 private constant REVOKE_TYPEHASH =
        keccak256("Revoke(bytes32 digest,address identity)");
    bytes32 private constant ISSUE_TYPEHASH =
        keccak256("Issue(bytes32 digest,uint256 exp,address identity)");
    bytes32 private constant ONHOLD_TYPEHASH =
        keccak256(
            "OnHold(bytes32 digest,address identity,bool onHoldStatus,uint64 nonce)"
        );

    bytes32 private constant ONHOLD_WITH_CUSTOM_DELEGATE_TYPE_TYPEHASH =
        keccak256(
            "OnHoldByDelegateWithCustomType(bytes32 digest,address identity,bool onHoldStatus,uint64 nonce,bytes32 delegateType)"
        );

    function issue(bytes32 digest, uint256 exp, address identity) external {
        _validateController(
            getDidRegistry(identity).didRegistry,
            _msgSender(),
            identity
        );
        _issue(identity, digest, exp);
    }

    function _issue(address by, bytes32 digest, uint256 exp) private {
        Detail memory detail = registers[digest][by];
        require(detail.iat == 0 && detail.exp == 0, "RAE");
        uint256 iat = block.timestamp;
        detail.iat = iat;
        detail.nonce++;
        if (exp > 0) {
            require(exp > block.timestamp, "IET");
            // just skipping exp if zero, to save gas
            detail.exp = exp;
        }

        registers[digest][by] = detail;
        emit NewIssuance(digest, by, iat, exp);
    }

    function update(bytes32 digest, uint256 exp, address identity) external {
        _validateController(
            getDidRegistry(identity).didRegistry,
            _msgSender(),
            identity
        );
        _update(digest, exp, identity);
    }

    function _update(bytes32 digest, uint256 exp, address by) private {
        Detail memory detail = registers[digest][by];
        require(!(detail.exp < block.timestamp && detail.exp != 0), "ER"); // not expiration check
        require(detail.iat > 0, "RNIBE"); // must be issued check
        if (exp != detail.exp) {
            // just skipping exp if zero, to save gas
            detail.exp = exp;
        }
        emit NewUpdate(digest, by, exp);
    }

    function revoke(bytes32 digest, address identity) external {
        _validateController(
            getDidRegistry(identity).didRegistry,
            _msgSender(),
            identity
        );
        _revoke(_msgSender(), digest);
    }

    function onHoldChange(
        bytes32 digest,
        address identity,
        bool onHoldStatus
    ) external {
        _validateController(
            getDidRegistry(identity).didRegistry,
            _msgSender(),
            identity
        );
        _onHoldChange(identity, digest, onHoldStatus);
    }

    function _onHoldChangeWithNonceManagement(
        address by,
        bytes32 digest,
        bool onHoldStatus,
        uint64 nonce
    ) private {
        Detail storage detail = registers[digest][by];
        _validateNonce(nonce, detail.nonce);
        _onHoldChangeCore(by, digest, onHoldStatus, detail);
    }

    function _onHoldChange(
        address by,
        bytes32 digest,
        bool onHoldStatus
    ) private {
        Detail storage detail = registers[digest][by];
        _onHoldChangeCore(by, digest, onHoldStatus, detail);
    }

    function _onHoldChangeCore(
        address by,
        bytes32 digest,
        bool onHoldStatus,
        Detail storage detail
    ) private {
        uint256 currentTime = block.timestamp;
        require(detail.exp > currentTime || detail.exp == 0, "ER");
        require(detail.onHold != onHoldStatus, "IOHCS");
        detail.onHold = onHoldStatus;
        detail.nonce++;
        emit NewOnHoldChange(digest, by, onHoldStatus, currentTime);
    }

    function onHoldChangeSigned(
        bytes32 digest,
        address identity,
        bool onHoldStatus,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(
            ONHOLD_TYPEHASH,
            digest,
            identity,
            onHoldStatus,
            nonce
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address didRegistry = getDidRegistry(identity).didRegistry;
        checkControllerSignature(
            didRegistry,
            identity,
            sigV,
            sigR,
            sigS,
            completeHash
        );
        _onHoldChangeWithNonceManagement(identity, digest, onHoldStatus, nonce);
    }

    function _revoke(address by, bytes32 digest) private {
        uint256 exp = block.timestamp;
        Detail storage detail = registers[digest][by];
        require(detail.exp > exp || detail.exp == 0, "ER");
        detail.exp = exp;
        detail.isRevoked = true;
        if (detail.onHold) {
            detail.onHold = false;
        }
        detail.nonce++;
        emit NewRevocation(digest, by, detail.iat, exp);
    }

    function getDetails(
        address issuer,
        bytes32 digest
    )
        external
        view
        returns (
            uint256 iat,
            uint256 exp,
            bool onHold,
            bool isRevoked,
            uint64 nonce
        )
    {
        Detail memory detail = registers[digest][issuer];
        iat = detail.iat;
        exp = detail.exp;
        onHold = detail.onHold;
        isRevoked = detail.isRevoked;
        nonce = detail.nonce;
    }

    function issueByDelegate(
        address identity,
        bytes32 digest,
        uint256 exp
    ) external {
        // resolve didRegistry to call
        address registryAddress = getDidRegistry(identity).didRegistry;

        _validateDelegate(
            registryAddress,
            identity,
            defaultDelegateType,
            _msgSender()
        );
        _issue(identity, digest, exp);
    }

    function issueByDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        uint256 exp
    ) external {
        _validateDelegateWithCustomType(delegateType, identity, _msgSender());
        _issue(identity, digest, exp);
    }

    function issueSigned(
        bytes32 digest,
        uint256 exp,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(
            ISSUE_TYPEHASH,
            digest,
            exp,
            identity
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);
        address didRegistry = getDidRegistry(identity).didRegistry;
        checkControllerSignature(
            didRegistry,
            identity,
            sigV,
            sigR,
            sigS,
            completeHash
        );
        _issue(identity, digest, exp);
    }

    function issueByDelegateSigned(
        bytes32 digest,
        uint256 exp,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes32 delegateType = _getDefaultDelegateType();
        _issueByDelegateSigned(
            delegateType,
            identity,
            digest,
            exp,
            sigV,
            sigR,
            sigS
        );
    }

    function issueByDelegateWithCustomDelegateTypeSigned(
        bytes32 delegateType,
        bytes32 digest,
        uint256 exp,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) public {
        require(isValidDelegateType(identity, delegateType), "DTNS");
        _issueByDelegateSigned(
            delegateType,
            identity,
            digest,
            exp,
            sigV,
            sigR,
            sigS
        );
    }

    function _issueByDelegateSigned(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        uint256 exp,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) private {
        bytes memory message = abi.encode(
            ISSUE_TYPEHASH,
            digest,
            exp,
            identity
        );
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);

        bytes32 dt = delegateType; // avoid stack too deep

        address didRegistry = getDidRegistry(identity).didRegistry;
        checkDelegateSignature(
            didRegistry,
            identity,
            sigV,
            sigR,
            sigS,
            completeHash,
            dt
        );
        _issue(identity, digest, exp);
    }

    function revokeSigned(
        bytes32 digest,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes memory message = abi.encode(REVOKE_TYPEHASH, digest, identity);
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash); // hash of: business data,contract name, eip712 version, address this, chainId, eip712 signature and salt
        address didRegistry = getDidRegistry(identity).didRegistry;
        checkControllerSignature(
            didRegistry,
            identity,
            sigV,
            sigR,
            sigS,
            completeHash
        );
        _revoke(identity, digest);
    }

    function revokeByDelegate(address identity, bytes32 digest) external {
        address registryAddress = getDidRegistry(identity).didRegistry;
        _validateDelegate(
            registryAddress,
            identity,
            defaultDelegateType,
            _msgSender()
        );
        _revoke(identity, digest);
    }

    function revokeByDelegateSigned(
        bytes32 digest,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes32 delegateType = _getDefaultDelegateType();
        _revokeByDelegateSigned(
            delegateType,
            identity,
            digest,
            sigV,
            sigR,
            sigS
        );
    }

    function revokeByDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        bytes32 digest
    ) external {
        _validateDelegateWithCustomType(delegateType, identity, _msgSender());
        _revoke(identity, digest);
    }

    function _revokeByDelegateSigned(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) private {
        bytes memory message = abi.encode(REVOKE_TYPEHASH, digest, identity);
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);

        bytes32 dt = delegateType; // avoid stack too deep

        address didRegistry = getDidRegistry(identity).didRegistry;
        checkDelegateSignature(
            didRegistry,
            identity,
            sigV,
            sigR,
            sigS,
            completeHash,
            dt
        );
        _revoke(identity, digest);
    }

    function revokeByDelegateWithCustomDelegateTypeSigned(
        bytes32 delegateType,
        bytes32 digest,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) public {
        require(isValidDelegateType(identity, delegateType), "DTNS");
        _revokeByDelegateSigned(
            delegateType,
            identity,
            digest,
            sigV,
            sigR,
            sigS
        );
    }

    function onHoldByDelegate(
        address identity,
        bytes32 digest,
        bool onHoldStatus
    ) external {
        // resolve didRegistry to call
        address registryAddress = getDidRegistry(identity).didRegistry;
        _validateDelegate(
            registryAddress,
            identity,
            defaultDelegateType,
            _msgSender()
        );
        _onHoldChange(identity, digest, onHoldStatus);
    }

    function onHoldByDelegateSigned(
        bytes32 digest,
        address identity,
        bool onHoldStatus,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        bytes32 delegateType = _getDefaultDelegateType();
        _onHoldByDelegateSigned(
            delegateType,
            identity,
            digest,
            onHoldStatus,
            nonce,
            sigV,
            sigR,
            sigS
        );
    }

    function _onHoldByDelegateSigned(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        bool onHoldStatus,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) private {
        bytes memory message = abi.encode(
            ONHOLD_TYPEHASH,
            digest,
            identity,
            onHoldStatus,
            nonce
        );
        __onHoldByDelegateSigned(
            delegateType,
            identity,
            digest,
            onHoldStatus,
            message,
            nonce,
            sigV,
            sigR,
            sigS
        );
    }

    function _onHoldByDelegateWithCustomTypeSigned(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        bool onHoldStatus,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) private {
        bytes memory message = abi.encode(
            ONHOLD_WITH_CUSTOM_DELEGATE_TYPE_TYPEHASH,
            digest,
            identity,
            onHoldStatus,
            nonce,
            delegateType
        );
        __onHoldByDelegateSigned(
            delegateType,
            identity,
            digest,
            onHoldStatus,
            message,
            nonce,
            sigV,
            sigR,
            sigS
        );
    }

    function __onHoldByDelegateSigned(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        bool onHoldStatus,
        bytes memory message,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) private {
        bytes32 structHash = keccak256(message);
        bytes32 completeHash = _hashTypedDataV4(structHash);

        bytes32 dt = delegateType; // avoid stack too deep

        address didRegistry = getDidRegistry(identity).didRegistry;
        checkDelegateSignature(
            didRegistry,
            identity,
            sigV,
            sigR,
            sigS,
            completeHash,
            dt
        );
        _onHoldChangeWithNonceManagement(identity, digest, onHoldStatus, nonce);
    }

    function onHoldByDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        bool onHoldStatus
    ) external {
        _validateDelegateWithCustomType(delegateType, identity, _msgSender());
        _onHoldChange(identity, digest, onHoldStatus);
    }

    function onHoldByDelegateWithCustomTypeSigned(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        bool onHoldStatus,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external {
        _onHoldByDelegateWithCustomTypeSigned(
            delegateType,
            identity,
            digest,
            onHoldStatus,
            nonce,
            sigV,
            sigR,
            sigS
        );
    }
}
