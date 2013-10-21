<?php

namespace Escape\WSSEAuthenticationBundle\Command;

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;

use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;

class DeleteNoncesCommand extends ContainerAwareCommand
{
    protected function configure()
    {
        $this
            ->setName('escape:wsseauthentication:nonces:delete')
            ->setDescription('Delete nonces')
            ->setDefinition(
                array(
                    new InputArgument('nonceDir', InputArgument::REQUIRED, 'nonce directory'),
                    new InputArgument('lifetime', InputArgument::REQUIRED, 'lifetime')
                )
            )
            ->setHelp(<<<EOT
The <info>escape:wsseauthentication:nonces:delete</info> command deletes all expired nonces:

<info>php app/console escape:wsseauthentication:nonces:delete</info>

This interactive shell will ask you for a nonceDir and a lifetime.

You can alternatively specify the nonceDir and lifetime arguments:

<info>php app/console escape:wsseauthentication:nonces:delete /path/to/security/nonces 300</info>
EOT
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $nonceDir = $input->getArgument('nonceDir');
        $lifetime = $input->getArgument('lifetime');

        $fs = new Filesystem();

        $finder = new Finder();

        $finder->files()->in($nonceDir);

        $i = 0;

        foreach($finder as $file)
        {
            if(file_get_contents($file->getRealPath()) + $lifetime < time())
            {
                $file = $file->getRealPath();

                $fs->remove($file);
                $i++;

                $output->writeln(sprintf('Deleted expired nonce <comment>%s</comment>.', $file));
            }
        }

        $output->writeln(
            sprintf(
                'Deleted <comment>%s</comment> expired nonces in <comment>%s</comment>.',
                $i,
                $nonceDir
            )
        );
    }

    protected function interact(InputInterface $input, OutputInterface $output)
    {
        if(!$input->getArgument('nonceDir'))
        {
            $arg = $this->getHelper('dialog')->askAndValidate(
                $output,
                'Please specify the nonceDir:',
                function($arg)
                {
                    if(empty($arg))
                    {
                        $error = 'nonceDir can not be empty';
                        $output->writeln(sprintf('<error>%s</error>',$error));

                        throw new Exception($error);
                    }

                    return $arg;
                }
            );

            $input->setArgument('nonceDir', $arg);
        }

        if(!$input->getArgument('lifetime'))
        {
            $arg = $this->getHelper('dialog')->askAndValidate(
                $output,
                'Please specify the lifetime:',
                function($arg)
                {
                    if(empty($arg))
                    {
                        $error = 'lifetime can not be empty';
                        $output->writeln(sprintf('<error>%s</error>',$error));

                        throw new Exception($error);
                    }

                    return $arg;
                }
            );

            $input->setArgument('lifetime', $arg);
        }
    }
}
