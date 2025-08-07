class ApplicationController < ActionController::API
  before_action :authenticate_user!

  private

  def authenticate_user!
    token = request.headers['Authorization']&.split(' ')&.last

    if token.present?
      begin
        decoded_token = JWT.decode(token, jwt_secret, true, { algorithm: 'HS256' })
        @current_user = User.find(decoded_token[0]['sub'])
      rescue JWT::DecodeError, ActiveRecord::RecordNotFound
        render json: { success: false, message: '認証に失敗しました' }, status: :unauthorized
      end
    else
      render json: { success: false, message: '認証情報が必要です' }, status: :unauthorized
    end
  end

  def current_user
    @current_user
  end

  def jwt_secret
    ENV['DEVISE_JWT_SECRET_KEY'] || Rails.application.secret_key_base
  end
end
