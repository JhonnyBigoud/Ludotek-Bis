<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class AppLoginAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'user_login';

    public function __construct(private UrlGeneratorInterface $urlGenerator)
    {
    }

    // Logique de la méthode d'identification
    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('email', '');
        // Request = variable POST
        $request->getSession()->set(Security::LAST_USERNAME, $email);

        return new Passport(
            new UserBadge($email),
            // Comment on retrouve l'utilisateur
            new PasswordCredentials($request->request->get('password', '')),
            // Prend en paramètre le mdp tapé, et vérifie le compte qui doit se connecter ?
            [
                new CsrfTokenBadge('authenticate', $request->request->get('_csrf_token')),
            ]
            // Envoyé en même temps que le formulaire, token permettant de vérifier le formulaire.
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
            // Permet de rediriger sur la page précédent la connexion après la connexion
        }

        return new RedirectResponse($this->urlGenerator->generate('main_index'));
        throw new \Exception('TODO: provide a valid redirect inside '.__FILE__);
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}
