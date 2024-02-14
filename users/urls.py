from django.urls import path
from .views import QuizHistoryView, QuizQuestionCreateView, QuizQuestionListView, RegisterView, LoginView, UserProfileUpdate, UserView, LogoutView,UserProfileView,QuestionHistoryDetailView, PhotoView, forgot_password, reset_password

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('quiz-history/', QuizHistoryView.as_view(), name='quiz_history'),
    path('questions/', QuizQuestionListView.as_view(), name='quiz_question_list'),
    path('quiz-questions/create/', QuizQuestionCreateView.as_view(), name='quiz_question_create'),
    path('update/',UserProfileUpdate.as_view(),name='Update'),
    path('userprofile/',UserProfileView.as_view(),name='UserProfile'),
    path('questionhistoryget/',QuestionHistoryDetailView.as_view(),name='history'),
    path('forgot_password/',forgot_password, name='forgot_password'),
    path('reset_password/', reset_password, name='reset_password'),



]
