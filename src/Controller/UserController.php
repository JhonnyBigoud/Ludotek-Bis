<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\RegisterType;
use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

#[Route('', name: 'user_')]
class UserController extends AbstractController
{
    #[Route('/login', name: 'login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
                return $this->redirectToRoute('main_index');
            }
            // get the login error if there is one
            $error = $authenticationUtils->getLastAuthenticationError();
            // last username entered by the user
            $lastUsername = $authenticationUtils->getLastUsername();
            
            return $this->render('user/login.html.twig', [
                'lastUsername' => $lastUsername,
                'error' => $error,
            ]);
        }
   
    
        

    #[Route('/register', name: 'register')]
    public function register(
        Request $request,
         UserPasswordHasherInterface $hasher,
         UserRepository $userRepository,
         ): Response
    {   
        $user = new User();
        $form = $this->createForm(RegisterType::class, $user);

        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            $hashed = $hasher->hashPassword($user, $user->getPlainPassword());
            $user->setPassword($hashed);

            $userRepository->add($user, true);
            $this->addFlash('success', 'Compte créé avec succès');
            return $this->redirectToRoute('user_login');
        }

        return $this->render('user/register.html.twig', [
            'form'=> $form->createView(),
        ]);
    }

    #[Route(path: '/logout', name: 'logout')]
    public function logout(): void
    {

    }
}