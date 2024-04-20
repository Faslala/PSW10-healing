from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import auth
from django.contrib.messages import constants
from django.contrib.messages import add_message
from django.http import HttpResponse

def cadastro(request):
    if request.method == 'GET':
        return render(request, 'cadastro.html')
    elif request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        senha = request.POST.get('senha')
        confirmar_senha = request.POST.get('confirmar_senha')
        
        if senha != confirmar_senha:
            add_message(request, constants.ERROR, 'A senha e o confirmar senha devem ser iguais.')
            return redirect('/usuarios/cadastro')
        
        if len(senha) < 6:
            add_message(request, constants.ERROR, 'A senha deve conter pelo menos 6 digitos.')
            return redirect('/usuarios/cadastro')
        
        user_check = User.objects.filter(username=username)
        if user_check.exists():
            add_message(request, constants.ERROR, 'Usuario ja existe com esse nome de usuario.')
            return redirect('/usuarios/cadastro')
        
        user = User.objects.create_user(
            username=username,
            email=email,
            password=senha
        )
        
        return redirect('/usuarios/login')      

def login_view(request):
    if request.method == "GET":
        return render(request, 'login.html')
    elif request.method == "POST":
        username = request.POST.get('username')
        senha = request.POST.get("senha")

        user = auth.authenticate(request, username=username, password=senha)

        if user:
            auth.login(request, user)
            return redirect('/pacientes/home')

        add_message(request, constants.ERROR, 'Usuário ou senha incorretos')
        return redirect('/usuarios/login')

def sair(request):
    auth.logout(request)
    return redirect('/usuario/login')