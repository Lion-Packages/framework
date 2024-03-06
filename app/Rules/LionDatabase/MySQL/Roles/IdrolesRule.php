<?php

declare(strict_types=1);

namespace App\Rules\LionDatabase\MySQL\Roles;

use Lion\Bundle\Helpers\Rules;
use Lion\Bundle\Interface\RulesInterface;
use Valitron\Validator;

/**
 * [Rule defined for the 'idroles' property]
 *
 * @package App\Rules\LionDatabase\MySQL\Roles
 */
class IdrolesRule extends Rules implements RulesInterface
{
	/**
	 * [field for 'idroles']
	 *
	 * @var string $field
	 */
	public string $field = 'idroles';

	/**
	 * [description for 'idroles']
	 *
	 * @var string $desc
	 */
	public string $desc = '';

	/**
	 * [value for 'idroles']
	 *
	 * @var string $value
	 */
	public string $value = '';

	/**
	 * [Defines whether the column is optional for postman collections]
	 *
	 * @var string $value
	 */
	public bool $disabled = false;

	/**
	 * {@inheritdoc}
	 * */
	public function passes(): void
	{
		$this->validate(function(Validator $validator) {
			$validator->rule('required', $this->field)->message('property is required');
		});
	}
}