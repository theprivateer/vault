<?php

namespace Vault\Console\Commands;

use Illuminate\Console\Command;
use Vault\Users\User;

class CreateUser extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'vault:user';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create a vault user';

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
        $user_email = $this->ask('New user email');

        $user = User::where('email', $user_email)->first();


        if( ! empty($user)) {
            $this->error('That user already exists');
        } else {
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

        $this->line('New user created');
    }
}
