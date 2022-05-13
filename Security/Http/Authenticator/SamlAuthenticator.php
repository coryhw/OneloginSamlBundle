<?php

declare(strict_types=1);

namespace Hslavich\OneloginSamlBundle\Security\Http\Authenticator;

use Hslavich\OneloginSamlBundle\Event\UserCreatedEvent;
use Hslavich\OneloginSamlBundle\Event\UserModifiedEvent;
use Hslavich\OneloginSamlBundle\Security\Http\Authenticator\Passport\Badge\SamlAttributesBadge;
use Hslavich\OneloginSamlBundle\Security\Http\Authenticator\Token\SamlToken;
use Hslavich\OneloginSamlBundle\Security\User\SamlUserFactoryInterface;
use Hslavich\OneloginSamlBundle\Security\User\SamlUserInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\LogicException;
use Symfony\Component\Security\Core\Exception\SessionUnavailableException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class SamlAuthenticator implements AuthenticatorInterface, AuthenticationEntryPointInterface
{
    private $httpUtils;
    private $userProvider;
    private $oneLoginAuth;
    private $successHandler;
    private $failureHandler;
    private $options;
    private $userFactory;
    private $eventDispatcher;
    private $logger;

    public function __construct(
        HttpUtils $httpUtils,
        UserProviderInterface $userProvider,
        \OneLogin\Saml2\Auth $oneLoginAuth,
        AuthenticationSuccessHandlerInterface $successHandler,
        AuthenticationFailureHandlerInterface $failureHandler,
        array $options,
        ?SamlUserFactoryInterface $userFactory,
        ?EventDispatcherInterface $eventDispatcher,
        ?LoggerInterface $logger
    ) {
        $this->httpUtils = $httpUtils;
        $this->userProvider = $userProvider;
        $this->oneLoginAuth = $oneLoginAuth;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
        $this->options = $options;
        $this->userFactory = $userFactory;
        $this->eventDispatcher = $eventDispatcher;
        $this->logger = $logger;
    }

    public function supports(Request $request): ?bool
    {
        error_log('checking supports');
        return $request->isMethod('POST')
            && $this->httpUtils->checkRequestPath($request, $this->options['check_path']);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        error_log('called start');
        return new RedirectResponse($this->httpUtils->generateUri($request, $this->options['login_path']));
    }

    public function authenticate(Request $request): Passport
    {
        error_log('start authenticate');
        if (!$request->hasSession()) {
            throw new SessionUnavailableException('This authentication method requires a session.');
        }

        if ($this->options['require_previous_session'] && !$request->hasPreviousSession()) {
            throw new SessionUnavailableException('Your session has timed out, or you have disabled cookies.');
        }
        error_log('pre process response');
        $this->oneLoginAuth->processResponse();
        error_log('post process response');
        if ($this->oneLoginAuth->getErrors()) {
            $errorReason = $this->oneLoginAuth->getLastErrorReason();
            error_log('Postprocess error: ' . $errorReason);
            if (null !== $this->logger) {
                $this->logger->error($errorReason);
            }
            throw new AuthenticationException($errorReason);
        }

        return $this->createPassport();
    }

    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        error_log('creating authenticated token');
        if (!$passport instanceof Passport) {
            throw new LogicException(sprintf('Passport should be an instance of "%s".', Passport::class));
        }

        return $this->createToken($passport, $firewallName);
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        error_log('creating token');
        if (!$passport->hasBadge(SamlAttributesBadge::class)) {
            throw new LogicException(sprintf('Passport should contains a "%s" badge.', SamlAttributesBadge::class));
        }

        /** @var SamlAttributesBadge $badge */
        $badge = $passport->getBadge(SamlAttributesBadge::class);
        error_log('got passport badge');
        return new SamlToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles(), $badge->getAttributes());
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        error_log('onauth success');
        return $this->successHandler->onAuthenticationSuccess($request, $token);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        error_log('onauth failure ' . $exception->getMessage());
        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }

    protected function createPassport(): Passport
    {
        $attributes = $this->extractAttributes();
        error_log('extracted attributes');
        $username = $this->extractUsername($attributes);
        error_log('extracted username ' . $username);
        $userBadge = new UserBadge(
            $username,
            function ($identifier) use ($attributes) {
                try {
                    error_log('loading userbadge');
                    $user = $this->userProvider->loadUserByIdentifier($identifier);
                    error_log('loaded userbadge');
                } catch (UserNotFoundException $exception) {
                    error_log('loading userbadge error ' . $exception->getMessage());
                    if (!$this->userFactory instanceof SamlUserFactoryInterface) {
                        throw $exception;
                    }
                    error_log('creating new user');
                    $user = $this->generateUser($identifier, $attributes);
                } catch (\Throwable $exception) {
                    error_log('creating user error ' . $exception->getMessage());
                    throw new AuthenticationException('The authentication failed.', 0, $exception);
                }

                if ($user instanceof SamlUserInterface) {
                    error_log('setting saml attributes');
                    $user->setSamlAttributes($attributes);
                    if ($this->eventDispatcher) {
                        error_log('dispatching usermodified event');
                        $this->eventDispatcher->dispatch(new UserModifiedEvent($user));
                    }
                }
                error_log('finishing userbadge creation');
                return $user;
            }
        );
        error_log('building selfvalidating passport');
        return new SelfValidatingPassport($userBadge, [new SamlAttributesBadge($attributes)]);
    }

    protected function extractAttributes(): array
    {
        error_log('extracting attributes');
        if (isset($this->options['use_attribute_friendly_name']) && $this->options['use_attribute_friendly_name']) {
            $attributes = $this->oneLoginAuth->getAttributesWithFriendlyName();
        } else {
            $attributes = $this->oneLoginAuth->getAttributes();
        }
        $attributes['sessionIndex'] = $this->oneLoginAuth->getSessionIndex();

        return $attributes;
    }

    protected function extractUsername(array $attributes): string
    {
        error_log('extracting username');
        if (isset($this->options['username_attribute'])) {
            if (!\array_key_exists($this->options['username_attribute'], $attributes)) {
                if (null !== $this->logger) {
                    $this->logger->error('Found attributes: '.print_r($attributes, true));
                }
                throw new \RuntimeException('Attribute "'.$this->options['username_attribute'].'" not found in SAML data');
            }

            return $attributes[$this->options['username_attribute']][0];
        }

        return $this->oneLoginAuth->getNameId();
    }

    protected function generateUser(string $username, array $attributes): UserInterface
    {
        error_log('generating user function');
        $user = $this->userFactory->createUser($username, $attributes);

        if ($this->eventDispatcher) {
            $this->eventDispatcher->dispatch(new UserCreatedEvent($user));
        }

        return $user;
    }
}
