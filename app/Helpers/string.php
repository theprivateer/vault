<?php

if( ! function_exists('parse_markdown'))
{
    function parse_markdown($str)
    {
        $str = trim($str);

        if (empty($str)) {
            return;
        }

        $environment = League\CommonMark\Environment::createCommonMarkEnvironment();
        $parser = new League\CommonMark\DocParser($environment);
        $htmlRenderer = new League\CommonMark\HtmlRenderer($environment);

        $text = $parser->parse($str);
        return $htmlRenderer->renderBlock($text);
    }
}

if( ! function_exists('alternator'))
{
    function alternator($args)
    {
        static $i;
        if (func_num_args() === 0) {
            $i = 0;

            return '';
        }
        $args = func_get_args();

        return $args[($i ++ % count($args))];
    }
}