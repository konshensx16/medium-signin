<?php

namespace App\Security;

use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class TokenAuthenticator extends AbstractGuardAuthenticator
{

    /**
     * @var EntityManagerInterface
     */
    private $entityManager;
    /**
     * @var UserRepository
     */
    private $userRepository;

    public function __construct(EntityManagerInterface $entityManager, UserRepository $userRepository)
    {
        $this->entityManager = $entityManager;
        $this->userRepository = $userRepository;
    }
    public function supports(Request $request)
    {
        dump('Yoo i was called');
        return $request->query->has('token');
    }

    public function getCredentials(Request $request)
    {
        $credentials = [
            'token' => $request->query->get('token'),
        ];

        return $credentials;
    }

    /**
     * @param mixed $credentials
     * @param UserProviderInterface $userProvider
     * @return \App\Entity\User|null|UserInterface
     * @throws \Exception
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $user = $this->userRepository->findOneBy(['token' => $credentials['token']]);

        if (!$user) {
            throw new \Exception("This token does not belong to anybody!");
        }

        return $user;
    }

    /**
     * @param mixed $credentials
     * @param UserInterface $user
     * @return bool
     * @throws \Exception
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        if ($credentials['token'] === $user->getToken()) {
            $user->setToken('');
            $this->entityManager->persist($user);
            $this->entityManager->flush();
            return true;
        }

        throw new \Exception('The token is useless, maybe try loggin in again');
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        throw $exception;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return 'Welcome home user with email: ' . $token->getUser()->getEmail();
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        // todo
    }

    public function supportsRememberMe()
    {
        // todo
    }
}
