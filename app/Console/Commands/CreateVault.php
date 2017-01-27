<?php

namespace Vault\Console\Commands;

use Illuminate\Console\Command;
use Vault\Users\User;

class CreateVault extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'vault:new';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create a new vault';

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
        $name = $this->ask('Vault name');

        if ($this->confirm('Set a vault passkey?')) {

            $passkey = $this->secret('Enter passkey');

            while ($this->secret('Confirm passkey') != $passkey)
            {
                $this->error('Passkey values do not match');
                $passkey = $this->secret('Enter passkey');
            }
        }

        $user_email = $this->ask('Owner of this vault (email)');

        $user = User::where('email', $user_email)->first();

        if( empty($user))
        {
            $this->line('User not found - creating a new one...');
            $user_name = $this->ask('Name of new user');
            $user_password = $this->secret('Password');

            while ($this->secret('Confirm password') != $user_password)
            {
                $this->error('Password values do not match');
                $user_password = $this->secret('Password');
            }

            $user = User::create([
                'name'  => $user_name,
                'email' => $user_email,
                'password'  => bcrypt($user_password)
            ]);
        }

        (new \Vault\Vaults\VaultRepository)->create([
            'name'          => $name,
            'passkey'       => (isset($passkey)) ? $passkey : null,
            'use_passkey'   => (isset($passkey))
        ], $user);

        $this->line('Creating vault...done');

    }
}
