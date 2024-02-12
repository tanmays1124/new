from django.urls import path
from .views import QuizHistoryView, QuizQuestionCreateView, QuizQuestionListView, RegisterView, LoginView, UserView, LogoutView

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('quiz-history/', QuizHistoryView.as_view(), name='quiz_history'),
    path('questions/', QuizQuestionListView.as_view(), name='quiz_question_list'),
    path('quiz-questions/create/', QuizQuestionCreateView.as_view(), name='quiz_question_create'),


]
