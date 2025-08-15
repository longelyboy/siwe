<?php
declare(strict_types=1);

namespace Zbkm\Siwe\Exception;

use RuntimeException;

class SiweInvalidMessageFieldException extends RuntimeException
{
    /** @var string */
    protected $field;

    /** @var string|int */
    protected $value;

    public function __construct(
        string $field,
               $value,
        array $conditions
    )
    {
        $message = "Invalid Sign-In with Ethereum message field \"$field\".\n";
        foreach ($conditions as $condition) {
            $message .= "\n- $condition";
        };
        $message .= "\n\nProvided value: {$value}";

        parent::__construct($message);
        $this->field = $field;
        $this->value = $value;
    }

    public function getField(): string
    {
        return $this->field;
    }

    /**
     * @return string|int
     */
    public function getValue()
    {
        return $this->value;
    }
}