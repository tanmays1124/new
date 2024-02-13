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
        email = request.data['username']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

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

class QuizQuestionListView(APIView):
    def get(self, request):
        quiz_questions = QuizQuestion.objects.all()
        serializer = QuizQuestionSerializer(quiz_questions, many=True)
        return Response(serializer.data)

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
