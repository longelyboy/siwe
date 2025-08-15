<?php
declare(strict_types=1);

namespace Zbkm\Siwe;

use DateTime;
use DateTimeInterface;
use Random\RandomException;
use Zbkm\Siwe\Validators\SiweMessageFieldValidator;

class SiweMessageParams
{
    const DEFAULT_VERSION = "1";

    /** @var string */
    public $address;
    /** @var int */
    public $chainId;
    /** @var string */
    public $domain;
    /** @var string */
    public $uri;
    /** @var DateTimeInterface|null */
    public $issuedAt;
    /** @var string|null */
    public $nonce;
    /** @var string|null */
    public $statement;
    /** @var string|null */
    public $version;
    /** @var string|null */
    public $scheme;
    /** @var DateTimeInterface|null */
    public $expirationTime;
    /** @var DateTimeInterface|null */
    public $notBefore;
    /** @var string|null */
    public $requestId;
    /** @var string[]|null */
    public $resources;

    /**
     * @param string $address The Ethereum address performing the signing
     * @param int $chainId Chain ID (1 for Ethereum)
     * @param string $domain The domain that is requesting the signing
     * @param string $uri An RFC 3986 URI referring to the resource that is the subject of the signing
     * @param DateTimeInterface|null $issuedAt The time when the message was generated
     * @param string|null $nonce A random string typically chosen by the relying party
     * @param string|null $statement A human-readable ASCII assertion
     * @param string|null $version The current version of the SIWE Message
     * @param string|null $scheme The URI scheme of the origin of the request
     * @param DateTimeInterface|null $expirationTime The time when the message is no longer valid
     * @param DateTimeInterface|null $notBefore The time when the message will become valid
     * @param string|null $requestId A system-specific identifier
     * @param string[]|null $resources A list of information or references
     * @throws RandomException
     */
    public function __construct(
        string $address,
        int $chainId,
        string $domain,
        string $uri,
        ?DateTimeInterface $issuedAt = null,
        ?string $nonce = null,
        ?string $statement = null,
        ?string $version = null,
        ?string $scheme = null,
        ?DateTimeInterface $expirationTime = null,
        ?DateTimeInterface $notBefore = null,
        ?string $requestId = null,
        ?array $resources = null
    ) {
        $this->address = $address;
        $this->chainId = $chainId;
        $this->domain = $domain;
        $this->uri = $uri;
        $this->issuedAt = $issuedAt;
        $this->nonce = $nonce;
        $this->statement = $statement;
        $this->version = $version;
        $this->scheme = $scheme;
        $this->expirationTime = $expirationTime;
        $this->notBefore = $notBefore;
        $this->requestId = $requestId;
        $this->resources = $resources;

        if ($this->issuedAt === null) {
            $this->issuedAt = new DateTime();
        }

        if ($this->nonce === null) {
            $this->nonce = NonceManager::generate();
        }

        if ($this->version === null) {
            $this->version = self::DEFAULT_VERSION;
        }

        $this->validate();
    }

    /**
     * Create Message Params from assoc array
     *
     * @param array $data
     * @return SiweMessageParams
     */
    public static function fromArray(array $data): self
    {
        return new self(
            $data["address"],
            $data["chainId"],
            $data["domain"],
            $data["uri"],
            $data["issuedAt"] ?? null,
            $data["nonce"] ?? null,
            $data["statement"] ?? null,
            $data["version"] ?? null,
            $data["scheme"] ?? null,
            $data["expirationTime"] ?? null,
            $data["notBefore"] ?? null,
            $data["requestId"] ?? null,
            $data["resources"] ?? null
        );
    }

    /**
     * Validate params
     */
    protected function validate(): void
    {
        SiweMessageFieldValidator::validateOrFail($this);
    }
}