<?php

namespace Vault\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\DB;
use Vault\Secrets\Secret;

class GenerateVaultKey extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'vault:key';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = '(Re)sets the vault encryption key';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $key = $this->generateRandomKey();

        $encrypter = new Encrypter(base64_decode(substr($key, 7)), $this->laravel['config']['vault.cipher']);

        $secrets = Secret::get();

        foreach($secrets as $secret)
        {
            $_key = $secret->key;
            $_value = $secret->value;

            DB::table('secrets')->where('id', $secret->id)
                ->update([
                    'key'   => $encrypter->encrypt($_key),
                    'value'   => $encrypter->encrypt($_value)
                ]);
        }


        $this->setKeyInEnvironmentFile($key);

        $this->info("Vault key [$key] set successfully.");
    }

    public function fire()
    {
        $key = $this->generateRandomKey();

        if ($this->option('show')) {
            return $this->line('<comment>'.$key.'</comment>');
        }

        // Next, we will replace the application key in the environment file so it is
        // automatically setup for this developer. This key gets generated using a
        // secure random byte generator and is later base64 encoded for storage.
        $this->setKeyInEnvironmentFile($key);

        $this->laravel['config']['app.key'] = $key;

        $this->info("Application key [$key] set successfully.");
    }

    /**
     * Set the application key in the environment file.
     *
     * @param  string  $key
     * @return void
     */
    protected function setKeyInEnvironmentFile($key)
    {
        $oldKey = ($this->laravel['config']['vault.key'] == $this->laravel['config']['app.key']) ? null : $this->laravel['config']['vault.key'];

        file_put_contents($this->laravel->environmentFilePath(), str_replace(
            'VAULT_KEY='.$oldKey,
            'VAULT_KEY='.$key,
            file_get_contents($this->laravel->environmentFilePath())
        ));
    }

    /**
     * Generate a random key for the application.
     *
     * @return string
     */
    protected function generateRandomKey()
    {
        return 'base64:'.base64_encode(random_bytes(
            $this->laravel['config']['vault.cipher'] == 'AES-128-CBC' ? 16 : 32
        ));
    }
}
