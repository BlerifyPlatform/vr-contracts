// SPDX-License-Identifier: APACHE-2.0

pragma solidity 0.8.18;

interface IVerificationRegistry {
    /**
     * An irreversible inital state that allows issuing entities to attest that an element (represented by the "digest") is valid and active
     * @param digest a unique identifier (typically a hash such as keccak256) defined at an application level
     * @param exp The time in the future at which an element will not be considered valid anymore
     * @param identity the identity on whose behalf the issuance is made
     *
     */
    function issue(bytes32 digest, uint256 exp, address identity) external;

    /**
     * An irreversible state indicating that an element (represented by the "digest") has been revoked by the issuing entity
     * @param digest a unique identifier (typically a hash such as keccak256) defined at an application level
     * @param identity the identity on whose behalf the revocation is made
     */
    function revoke(bytes32 digest, address identity) external;

    /**
     * A digest can only be updated in the expiration time
     * If such digest is revoked it throws an exception
     * If such digest is not issued it throws an exception
     */
    function update(bytes32 digest, uint256 exp, address identity) external;

    /**
     * A reversible state indicating that an element (represented by the "digest") has been placed under "observation" by the issuing entity
     * @param digest a unique identifier (typically a hash such as keccak256) defined at an application level
     * @param identity the identity on whose behalf the on-hold state change is made
     * @param onHoldStatus When "true" it indicates that an element (represented by the "digest") will be put on "observation" and
     * thus shouldn't be considered valid nor revoked. When false, the method restores the element to a active and thus valid state
     */
    function onHoldChange(
        bytes32 digest,
        address identity,
        bool onHoldStatus
    ) external;

    /**
     * @dev Returns details about an issued digest.
     * @notice See "Detail" struct on this documentation.
     */
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
        );

    /**
     * Optional way to register a data change. In this case an authorized the delegate sends the data on behalf of the main actor
     *
     */
    function issueByDelegate(
        address identity,
        bytes32 digest,
        uint256 exp
    ) external;

    /**
     * Optional way to revoke a data change. In this case an authorized delegate sends the data on behalf of the main actor
     *
     */
    function revokeByDelegate(address identity, bytes32 digest) external;

    /**
     * Optional way to update the expiration date of an element. In this case an authorized delegate sends the data on behalf of the main actor
     *
     */
    function onHoldByDelegate(
        address identity,
        bytes32 digest,
        bool onHoldStatus
    ) external;

    /**
     * @param delegateType: must match with a delegate that was registered under the "identity" using the method "addDelegateType"
     * Optional way to register a data change. In this case an authorized delegate sends the data on behalf of the main actor
     * @notice for further clarification, check "issue" method description
     *
     */
    function issueByDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        uint256 exp
    ) external;

    /**
     * @param delegateType: must match with a delegate that was registered under the "identity" using the method "addDelegateType"
     * Optional way to revoke an element. In this case an authorized delegate sends the data on behalf of the main actor
     * @notice for further clarification, check "revoke" method description
     *
     */
    function revokeByDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        bytes32 digest
    ) external;

    /**
     * @param delegateType: must match with a delegate that was registered under the "identity" using the method "addDelegateType"
     * Optional way to place or restore an element to/from on-hold state. In this case an authorized delegate sends the data on behalf of the main actor
     * @notice for further clarification, check "onHoldChange" method description
     *
     */
    function onHoldByDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        bool onHoldStatus
    ) external;

    /**
     * Optional way to place an element in the "issue" state. In this case the entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "issue" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function issueSigned(
        bytes32 digest,
        uint256 exp,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * Optional way to place an element in the "revoke" state. In this case the entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "revoke" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function revokeSigned(
        bytes32 digest,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * Optional way to update the expiration date of an element. In this case the delegate of an entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "update" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function updateSigned(
        bytes32 digest,
        uint256 exp,
        address identity,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * Optional way to place an element in the "on-hold" state. In this case the entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "onHoldChange" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function onHoldChangeSigned(
        bytes32 digest,
        address identity,
        bool onHoldStatus,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * Optional way to place an element in the "issue" state. In this case the delegate of an entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "issue" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function issueByDelegateSigned(
        bytes32 digest,
        uint256 exp,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * Optional way to place an element in the "revoke" state. In this case the delegate of an entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "revoke" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function revokeByDelegateSigned(
        bytes32 digest,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * Optional way to place an element in the "on-hold" state. In this case the delegate of an entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "onHoldChange" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function onHoldByDelegateSigned(
        bytes32 digest,
        address identity,
        bool onHoldStatus,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * Optional way to update the expiration date of an element. In this case the delegate of an entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "update" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function updateByDelegateSigned(
        bytes32 digest,
        uint256 exp,
        address identity,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * @param delegateType: must match with a delegate that was registered under the "identity" using the method "addDelegateType"
     * Optional way to place an element in the "issue" state. In this case the delegate of an entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "issue" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function issueByDelegateWithCustomDelegateTypeSigned(
        bytes32 delegateType,
        bytes32 digest,
        uint256 exp,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * @param delegateType: must match with a delegate that was registered under the "identity" using the method "addDelegateType"
     * Optional way to place an element in the "revoke" state. In this case the delegate of an entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "revoke" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function revokeByDelegateWithCustomDelegateTypeSigned(
        bytes32 delegateType,
        bytes32 digest,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * @param delegateType: must match with a delegate that was registered under the "identity" using the method "addDelegateType"
     * Optional way to place an element in the "on-hod" state. In this case the delegate of an entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "onHoldChange" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function onHoldByDelegateWithCustomTypeSigned(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        bool onHoldStatus,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    /**
     * @param delegateType: must match with a delegate that was registered under the "identity" using the method "addDelegateType"
     * Optional way to update the expiration date of an element. In this case the delegate of an entity sends the data using an EIP-712 signed transaction
     * @notice for further clarification, check "update" method description
     * @param sigV ecdsa signature component
     * @param sigR ecdsa signature component
     * @param sigS ecdsa signature component
     *
     */
    function updateByDelegateWithCustomTypeSigned(
        bytes32 delegateType,
        bytes32 digest,
        uint256 exp,
        address identity,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    event NewIssuance(
        bytes32 indexed digest,
        address indexed by,
        uint iat,
        uint exp
    );

    event NewUpdate(bytes32 indexed digest, address indexed by, uint exp);

    /**
     * Adding iat to the log allows verfying if the credential was actually issued onchan in the past(iat>0) or 
     just revoked (iat = 0)
     */
    event NewRevocation(
        bytes32 indexed digest,
        address indexed by,
        uint iat,
        uint exp
    );

    /**
     * @dev OnHoldChange is a toggle that indicates the status of some data represented by a "digest". If "isOnHold" is true it indicates that the data is
     * in observation, so meanwhile that data should be taken into temporal status.
     */
    event NewOnHoldChange(
        bytes32 indexed digest,
        address indexed by,
        bool isOnHold,
        uint256 currentTime
    );

    /**
     * @param iat: date at which a data was issued
     * @param exp: date at which the data is expiring
     * @param OnHold: indicates whether the data is under observation
     * @param nonce: increments with every state change
     * @note:
     scenario 1: !(iat = 0 && exp = 0 && onHold = false && isRevoked = false), means data "exists" given an issuer, a digest for the context of this contract.
     scenario 2: iat > 0 && 0 < exp < currentTime -> "expired"
     scenario 3: isRevoked -> data attestation has been "revoked"
     */
    struct Detail {
        uint256 iat;
        uint256 exp;
        bool onHold;
        bool isRevoked;
        uint64 nonce;
    }
}
