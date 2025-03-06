// SPDX-License-Identifier: APACHE-2.0

pragma solidity 0.8.18;

interface IVerificationRegistry {
    /**
     * Once revoked it will not longer be valid
     */
    function issue(bytes32 digest, uint256 exp, address identity) external;

    function revoke(bytes32 digest, address identity) external;

    /**
     * A digest can only be updated in the expiration time
     * If such digest is revoked it throws an exception
     * If such digest is not issued it throws an exception
     */
    function update(bytes32 digest, uint256 exp, address identity) external;

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
     * Optional way to register a data change. In this case the delegate sends the data on behalf of the main actor
     *
     */
    function issueByDelegate(
        address identity,
        bytes32 digest,
        uint256 exp
    ) external;

    function revokeByDelegate(address identity, bytes32 digest) external;

    function onHoldByDelegate(
        address identity,
        bytes32 digest,
        bool onHoldStatus
    ) external;

    /**
     * @param delegateType: must coincide with some delegate that was registered under the "identity" by using the method "addDelegateType"
     * Optional way to register a data change. In this case the delegate sends the data on behalf of the main actor
     */
    function issueByDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        uint256 exp
    ) external;

    function revokeByDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        bytes32 digest
    ) external;

    function onHoldByDelegateWithCustomType(
        bytes32 delegateType,
        address identity,
        bytes32 digest,
        bool onHoldStatus
    ) external;

    function issueSigned(
        bytes32 digest,
        uint256 exp,
        address identity,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    function revokeSigned(
        bytes32 digest,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    function issueByDelegateSigned(
        bytes32 digest,
        uint256 exp,
        address identity,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    function revokeByDelegateSigned(
        bytes32 digest,
        address identity,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    function issueByDelegateWithCustomDelegateTypeSigned(
        bytes32 delegateType,
        bytes32 digest,
        uint256 exp,
        address identity,
        uint64 nonce,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    function revokeByDelegateWithCustomDelegateTypeSigned(
        bytes32 delegateType,
        bytes32 digest,
        address identity,
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
