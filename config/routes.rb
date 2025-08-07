Rails.application.routes.draw do
  # 既存のDeviseルート（管理用として残す）
  devise_for :users, skip: :all

  # API用のルート
  namespace :api do
    resource :auth, only: [], controller: 'auth' do
      post :register
      post :login
      delete :logout
      get :me

      # メール確認
      post :confirmation, action: :send_confirmation
      get :confirmation, action: :confirm_email

      # パスワードリセット
      post :password, action: :send_reset_password_instructions
      put :password, action: :reset_password

      # パスワード変更（ログイン済み）
      put 'password/change', action: :change_password
    end
  end

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
