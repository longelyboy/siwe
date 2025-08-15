<?php
declare(strict_types=1);

namespace Zbkm\Siwe;

use DateTimeInterface;
use Zbkm\Siwe\Exception\SiweInvalidMessageFieldException;

class SiweMessageParamsBuilder
{
    /** @var string */
    protected $address;
    /** @var int */
    protected $chainId;
    /** @var string */
    protected $domain;
    /** @var string|null */
    protected $statement;
    /** @var DateTimeInterface|null */
    protected $expirationTime;
    /** @var DateTimeInterface|null */
    protected $issuedAt;
    /** @var DateTimeInterface|null */
    protected $notBefore;
    /** @var string|null */
    protected $requestId;
    /** @var string|null */
    protected $scheme;
    /** @var string|null */
    protected $nonce;
    /** @var string */
    protected $uri;
    /** @var string|null */
    protected $version;
    /** @var array|null */
    protected $resources;

    protected function __construct()
    {
    }

    /**
     * @return self
     */
    public static function create(): self
    {
        return new self();
    }

    /**
     * @param string $address The Ethereum address performing the signing
     * @return self
     */
    public function withAddress(string $address): self
    {
        $this->address = $address;
        return $this;
    }

    /**
     * @param int $chainId Chain ID (1 for Ethereum)
     * @return self
     */
    public function withChainId(int $chainId): self
    {
        $this->chainId = $chainId;
        return $this;
    }

    /**
     * @param string $domain The domain that is requesting the signing
     * @return self
     */
    public function withDomain(string $domain): self
    {
        $this->domain = $domain;
        return $this;
    }

    /**
     * @param string $statement A human-readable ASCII assertion that the user will sign which MUST NOT include '\n'
     * @return self
     */
    public function withStatement(string $statement): self
    {
        $this->statement = $statement;
        return $this;
    }

    /**
     * @param DateTimeInterface $expirationTime The time when the signed authentication message is no longer valid
     * @return self
     */
    public function withExpirationTime(DateTimeInterface $expirationTime): self
    {
        $this->expirationTime = $expirationTime;
        return $this;
    }

    /**
     * @param DateTimeInterface $issuedAt The time when the message was generated, typically the current time
     * @return self
     */
    public function withIssuedAt(DateTimeInterface $issuedAt): self
    {
        $this->issuedAt = $issuedAt;
        return $this;
    }

    /**
     * @param DateTimeInterface $notBefore The time when the signed authentication message will become valid
     * @return self
     */
    public function withNotBefore(DateTimeInterface $notBefore): self
    {
        $this->notBefore = $notBefore;
        return $this;
    }

    /**
     * @param string $requestId A system-specific identifier that MAY be used to uniquely refer to the sign-in request
     * @return self
     */
    public function withRequestId(string $requestId): self
    {
        $this->requestId = $requestId;
        return $this;
    }

    /**
     * @param string $scheme The URI scheme of the origin of the request
     * @return self
     */
    public function withScheme(string $scheme): self
    {
        $this->scheme = $scheme;
        return $this;
    }

    /**
     * @param string $nonce A random string typically chosen by the relying party and used to prevent replay attacks, at least 8 alphanumeric characters
     * @return self
     */
    public function withNonce(string $nonce): self
    {
        $this->nonce = $nonce;
        return $this;
    }

    /**
     * @param string $uri An RFC 3986 URI referring to the resource that is the subject of the signing (as in the subject of a claim)
     * @return self
     */
    public function withUri(string $uri): self
    {
        $this->uri = $uri;
        return $this;
    }

    /**
     * @param string $version The current version of the SIWE Message, which MUST be 1 for this specification
     * @return self
     */
    public function withVersion(string $version): self
    {
        $this->version = $version;
        return $this;
    }

    /**
     * @param array $resources A list of information or references to information the user wishes to have resolved as part of authentication by the relying party
     * @return self
     */
    public function withResources(array $resources): self
    {
        $this->resources = $resources;
        return $this;
    }

    /**
     * Create Params for transfers to SiweMessage class
     *
     * @return SiweMessageParams
     * @throws \Exception
     */
    public function build(): SiweMessageParams
    {
        $requiredFields = ['address', 'chainId', 'domain', 'uri'];

        foreach ($requiredFields as $field) {
            if (!isset($this->$field)) {
                throw new SiweInvalidMessageFieldException($field, "", ["Required fields are not set"]);
            }
        }

        return new SiweMessageParams(
            $this->address,
            $this->chainId,
            $this->domain,
            $this->uri,
            $this->issuedAt,
            $this->nonce,
            $this->statement,
            $this->version,
            $this->scheme,
            $this->expirationTime,
            $this->notBefore,
            $this->requestId,
            $this->resources
        );
    }
}