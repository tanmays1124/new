from django.http import JsonResponse
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer, UserUpdateSerializer
from .models import User
import jwt, datetime
from rest_framework import status, generics


# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginView(APIView):
    def post(self, request):
        data = request.data['username']
        password = request.data['password']

        if '@' in data:
            user = User.objects.filter(email=data).first()
        else:
            user = User.objects.filter(username=data).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token,
            'id' : user.id
        }
        return response


class UserView(APIView):

    def get(self, request):
        authorization_header = request.headers.get('Authorization')

        if not authorization_header:
            raise AuthenticationFailed('Authorization header is missing')

        parts = authorization_header.split()

        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationFailed('Invalid Authorization header format')

        token = parts[1]


        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)
    
    def delete(self, request):
        authorization_header = request.headers.get('Authorization')

        if not authorization_header:
            raise AuthenticationFailed('Authorization header is missing')

        parts = authorization_header.split()

        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationFailed('Invalid Authorization header format')

        token = parts[1]


        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()
        user.delete()
        return Response({"Success":"User Deleted Successfully"})

class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response




from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .models import QuizHistory
from .serializers import QuizHistorySerializer
import jwt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .models import QuizHistory
from .serializers import QuizHistorySerializer
import jwt

class QuizHistoryView(APIView):
    def get(self, request):
        authorization_header = request.headers.get('Authorization')

        if not authorization_header:
            raise AuthenticationFailed('Authorization header is missing')

        parts = authorization_header.split()

        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationFailed('Invalid Authorization header format')

        token = parts[1]

        

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user_id = payload['id']
        print(user_id)
        quiz_histories = QuizHistory.objects.filter(user_id=user_id)
        serializer = QuizHistorySerializer(quiz_histories, many=True)
        return Response(serializer.data)



    def post(self, request):
        authorization_header = request.headers.get('Authorization')

        if not authorization_header:
            raise AuthenticationFailed('Authorization header is missing')

        parts = authorization_header.split()

        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationFailed('Invalid Authorization header format')

        token = parts[1]

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])

            user_id = payload.get('id')

            print(user_id)
            request.data['user'] = user_id
            print(request.data)
            serializer = QuizHistorySerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

            # Perform further processing here...

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')






from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .models import QuizQuestion
from .serializers import QuizQuestionSerializer
import jwt
from django.db.models import Q


class QuizQuestionListView(generics.ListAPIView):
    serializer_class = QuizQuestionSerializer

    def get_queryset(self):
        queryset = QuizQuestion.objects.all()
        print(self.request.headers)
        category = self.request.query_params.get('category', None)
        num_questions = self.request.query_params.get('num_questions', None)
        difficulty = self.request.query_params.get('difficulty', None)
        
        authorization_header = self.request.headers.get('Authorization')
        print('hi',authorization_header)

        if not authorization_header:
            raise AuthenticationFailed('Authorization header is missing')
        
        parts = authorization_header.split()

        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationFailed('Invalid Authorization header format')

        token = parts[1]
        print(token)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])

            user_id = payload.get('id')
            print(user_id)
        except:
            return Response('Unauthenticated')


        if category:
            queryset = queryset.filter(category=category)
        if difficulty:
            queryset = queryset.filter(difficulty=difficulty.lower())

        
        if user_id:
            user_history = QuizHistory.objects.filter(user=user_id)
            attempted_questions_texts = []
            for history in user_history:
                for attempted_question in history.attempted_questions:
                    attempted_questions_texts.append(attempted_question['q_text'])


            query = Q()
            for question_text in attempted_questions_texts:
                query |= Q(question=question_text)
            queryset = queryset.exclude(query)

        if num_questions:
            queryset = queryset[:int(num_questions)]
        print(queryset)

        return queryset

class QuizQuestionCreateView(APIView):
    def post(self, request):
        serializer = QuizQuestionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)






from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer

class UserProfileUpdate(APIView):

    def put(self, request):
        authorization_header = request.headers.get('Authorization')

        if not authorization_header:
            raise AuthenticationFailed('Authorization header is missing')

        parts = authorization_header.split()

        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationFailed('Invalid Authorization header format')

        token = parts[1]
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])

            user_id = payload.get('id')

            user = User.objects.filter(id=user_id).first()
        except:
            return Response('Unauthenticated')
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)




class QuestionHistoryDetailView(generics.ListAPIView):
    serializer_class = QuizHistorySerializer

    def get_queryset(self):
        queryset = QuizHistory.objects.all()

        # Get parameters from the request, default to None if not provided
        user_id = self.request.query_params.get('user_id', None)
        difficulty_level = self.request.query_params.get('difficulty_level', None)
        domain = self.request.query_params.get('domain', None)
        # user_id = self.request.query_params.get('user_id', None)


        # Apply filters based on parameters
        if user_id:
            queryset = queryset.filter(user=user_id)
        if user_id:
            queryset = queryset.filter(difficulty_level=difficulty_level)
        if user_id:
            queryset = queryset.filter(doamin=domain)

        print(queryset)

        return queryset
    

class UserProfileView(generics.ListAPIView):
    serializer_class = UserSerializer

    def get_queryset(self):
        queryset = User.objects.all()

        user_id = self.request.query_params.get('user_id', None)
        if user_id:
            queryset = queryset.filter(id=user_id)
        print(queryset)

        return queryset
    



from rest_framework.decorators import api_view

class PhotoView:

    def put(request):
        authorization_header = request.headers.get('Authorization')

        if not authorization_header:
            raise AuthenticationFailed('Authorization header is missing')

        parts = authorization_header.split()

        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationFailed('Invalid Authorization header format')

        token = parts[1]
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])

            user_id = payload.get('id')

            user = User.objects.filter(id=user_id).first()
        except:
            return Response('Unauthenticated')
        
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)




from django.utils.http import  urlsafe_base64_decode
from django.core.mail import send_mail
from django.urls import reverse
import base64
from django.shortcuts import get_object_or_404
from django.contrib.auth.tokens import default_token_generator
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages



import users.ip as ip
@csrf_exempt
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        print(email)
        try:
            print("a")
            user = User.objects.get(email=email)
            print("aa")
        except User.DoesNotExist:
            messages.error(request, "User with this email address does not exist.")
            return render(request, 'get_email.html')

        token = default_token_generator.make_token(user)
        uid_bytes = str(user.pk).encode('utf-8')
        uid = base64.urlsafe_b64encode(uid_bytes).decode('utf-8')
        print(user.pk,uid)

        reset_link = request.build_absolute_uri(
            reverse('reset_password') + f'?uid={uid}&token={token}'
        )
        send_mail(
            'Reset Your Password',
            f'Click the following link to reset your password: {reset_link}',
            'from@example.com',
            [email],
            fail_silently=False,
        )
        return render(request, 'mail_sent.html',{'email':email,'ip':ip.ip})
    elif request.method == 'GET':
        print("haha")
        # Handle GET request if needed, for example, you can render a form to collect email
        return render(request, 'get_email.html')

    else:
        return JsonResponse({'error': 'Invalid request method.'}, status=400)




@csrf_exempt
def reset_password(request):
    if request.method == 'POST':
        print(request.GET)

        uid = request.POST.get('uid')
        token = request.POST.get('token')
        print("a",uid,token)
        pass1 = request.POST.get('new_password')
        pass2 = request.POST.get('confirm_password')

        if pass1!=pass2:
            messages.error(request,"Password doesn't match")
            return render(request, 'new.html',{"uid":uid,"token":token})

        user_id = urlsafe_base64_decode(uid).decode('utf-8')
        user = User.objects.get(id=user_id)
        if default_token_generator.check_token(user, token):
            new_password = request.POST.get('new_password')
            user.set_password(new_password)
            user.save()
            return render(request, 'success.html',{'ip':ip.ip})

        else:
            return JsonResponse({'error': 'Invalid or expired reset token.'}, status=400)
    elif request.method == 'GET':
        print(request.GET)
        # Handle GET request if needed, for example, you can render a form to reset password
        uid = request.GET['uid']
        token = request.GET['token']
        return render(request, 'new.html',{"uid":uid,"token":token})

    else:
        return JsonResponse({'error': 'Invalid request method.'}, status=400)