<?php

namespace Vault\Secrets;


use Laracasts\Presenter\Presenter;

class SecretPresenter extends Presenter
{

    public function value()
    {
        if($lockbox = $this->entity->linkedLockbox)
        {
            return link_to_route('lockbox.show', $lockbox->name, $lockbox->uuid, ['target' => '_blank']);
        } elseif($this->entity->paranoid)
        {
            $characters = (strlen($this->entity->value) > 16) ? 16 : strlen($this->entity->value);

            return str_repeat('&bull;', $characters);
        }

        // Detect URLS
        $reg_exUrl = "/(http|https|ftp|ftps)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?/";

        if(preg_match($reg_exUrl, $this->entity->value, $url)) {

            // make the urls hyper links
            return preg_replace($reg_exUrl, "<a href=\"{$url[0]}\" target=\"_blank\">{$url[0]}</a> ", $this->entity->value);

        }

        return $this->entity->value;

    }
}