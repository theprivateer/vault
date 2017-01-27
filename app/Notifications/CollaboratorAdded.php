<?php

namespace Vault\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Notification;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Vault\Users\User;
use Vault\Vaults\Vault;

class CollaboratorAdded extends Notification
{
    use Queueable;
    /**
     * @var Vault
     */
    private $vault;
    /**
     * @var User
     */
    private $user;

    /**
     * Create a new notification instance.
     *
     * @param User $user
     * @param Vault $vault
     */
    public function __construct(User $user, Vault $vault)
    {

        $this->vault = $vault;
        $this->user = $user;
    }

    /**
     * Get the notification's delivery channels.
     *
     * @param  mixed  $notifiable
     * @return array
     */
    public function via($notifiable)
    {
        return ['mail'];
    }

    /**
     * Get the mail representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return \Illuminate\Notifications\Messages\MailMessage
     */
    public function toMail($notifiable)
    {
        return (new MailMessage)
                    ->greeting('You have been added to a Vault')
                    ->line( $this->user->name . ' has added you as a collaborator to their vault.')
                    ->action('Go to Vault', route('vault.show', $this->vault->uuid))
                    ->line('Thank you for using our application!');
    }

    /**
     * Get the array representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return array
     */
    public function toArray($notifiable)
    {
        return [
            //
        ];
    }
}
