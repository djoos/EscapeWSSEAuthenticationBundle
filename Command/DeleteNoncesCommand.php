<?php

namespace Escape\WSSEAuthenticationBundle\Command;

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;

use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

use Doctrine\Common\Cache\Cache;

use \RunTimeException;

class DeleteNoncesCommand extends ContainerAwareCommand
{
    protected function configure()
    {
        $this
            ->setName('escape:wsseauthentication:nonces:delete')
            ->setDescription('Delete nonces')
            ->setDefinition(
                array(
                    new InputArgument('firewall', InputArgument::REQUIRED, 'firewall')
                )
            )
            ->setHelp(<<<EOT
The <info>escape:wsseauthentication:nonces:delete</info> command deletes all expired nonces:

<info>php app/console escape:wsseauthentication:nonces:delete</info>

This interactive shell will ask you for a firewall.

You can alternatively specify the firewall argument:

<info>php app/console escape:wsseauthentication:nonces:delete secured_area</info>
EOT
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $firewall = $input->getArgument('firewall');

        $wsse_authentication_provider = $this->getContainer()->get(
            sprintf(
                '%s.%s',
                'escape_wsse_authentication.provider',
                $firewall
            )
        );

        $nonceCache = $wsse_authentication_provider->getNonceCache();

        if(!($nonceCache instanceof Cache))
        {
            throw new RunTimeException('invalid cache');
        }

        //@todo only flush *expired* ones
        //...via some getIds() method and then check or a (future) built-in Doctrine cache function?
        $nonceCache->flushAll();

        $output->writeln(
            sprintf(
                'Deleted nonce cache ids for <comment>%s</comment> firewall.',
                $firewall
            )
        );
    }

    protected function interact(InputInterface $input, OutputInterface $output)
    {
        if(!$input->getArgument('firewall'))
        {
            $arg = $this->getHelper('dialog')->askAndValidate(
                $output,
                'Please specify a firewall:',
                function($arg)
                {
                    if(empty($arg))
                    {
                        throw new RunTimeException('firewall can not be empty');
                    }

                    return $arg;
                }
            );

            $input->setArgument('firewall', $arg);
        }
    }
}
