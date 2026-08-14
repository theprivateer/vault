<?php

namespace App\Console\Commands;

use App\Models\Invite;
use App\Models\User;
use Illuminate\Console\Command;

/**
 * Issues an invitation.
 *
 * Registration is closed (D11), so this is how the first account is created and
 * how every account after it begins. The invite authorises account creation and
 * nothing else — it carries no key material, and being invited grants access to
 * no vault.
 */
class InviteUser extends Command
{
    protected $signature = 'vault:invite
                            {email : The email address to invite}
                            {--days=7 : How many days the invitation remains valid}';

    protected $description = 'Issue an invitation to create an account';

    public function handle(): int
    {
        $email = strtolower(trim((string) $this->argument('email')));

        if (! filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->components->error("[{$email}] is not a valid email address.");

            return self::FAILURE;
        }

        if (User::where('email', $email)->exists()) {
            $this->components->error("An account already exists for [{$email}].");

            return self::FAILURE;
        }

        $token = Invite::generateToken();

        $invite = Invite::create([
            'email' => $email,
            'token_hash' => Invite::hashToken($token),
            'expires_at' => now()->addDays((int) $this->option('days')),
        ]);

        $this->newLine();
        $this->components->info("Invitation issued for {$email}");
        $this->line('  '.route('register', ['token' => $token]));
        $this->newLine();
        $this->components->warn('Expires '.$invite->expires_at->toDayDateTimeString().'. The link is shown once.');

        return self::SUCCESS;
    }
}
