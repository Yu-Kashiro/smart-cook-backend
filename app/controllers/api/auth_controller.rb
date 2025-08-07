class Api::AuthController < ApplicationController
  skip_before_action :authenticate_user!, except: [:me, :logout, :change_password]

  # POST /api/auth/register
  def register
    user = User.new(user_params)
    user.confirm! # Automatically confirm the user

    if user.save
      render_success(
        data: {
          user: user_data(user),
          token: jwt_token_for(user)
        },
        message: 'ユーザー登録が完了しました',
        status: :created
      )
    else
      render_error(
        errors: format_validation_errors(user.errors),
        message: '登録に失敗しました',
        status: :unprocessable_entity
      )
    end
  end

  # POST /api/auth/login
  def login
    user = User.find_by(email: params[:email])

    if user&.valid_password?(params[:password])
      if user.confirmed?
        render_success(
          data: {
            user: user_data(user),
            token: jwt_token_for(user)
          },
          message: 'ログインしました'
        )
      else
        render_error(
          errors: [{ field: 'email', message: 'メールアドレスが確認されていません' }],
          message: 'メールアドレスの確認が必要です',
          status: :unauthorized
        )
      end
    else
      render_error(
        errors: [{ field: 'credentials', message: 'メールアドレスまたはパスワードが正しくありません' }],
        message: 'ログインに失敗しました',
        status: :unauthorized
      )
    end
  end

  # DELETE /api/auth/logout
  def logout
    current_user.update_jti if current_user
    render_success(message: 'ログアウトしました')
  end

  # GET /api/auth/me
  def me
    render_success(
      data: { user: user_data(current_user) },
      message: 'ユーザー情報を取得しました'
    )
  end

  # POST /api/auth/confirmation
  def send_confirmation
    user = User.find_by(email: params[:email])

    if user
      if user.confirmed?
        render_error(
          errors: [{ field: 'email', message: 'すでにメールアドレスが確認されています' }],
          message: 'メールアドレスは確認済みです',
          status: :unprocessable_entity
        )
      else
        user.send_confirmation_instructions
        render_success(message: '確認メールを送信しました')
      end
    else
      render_error(
        errors: [{ field: 'email', message: 'メールアドレスが見つかりません' }],
        message: 'ユーザーが見つかりません',
        status: :not_found
      )
    end
  end

  # GET /api/auth/confirmation
  def confirm_email
    user = User.confirm_by_token(params[:confirmation_token])

    if user.errors.empty?
      render_success(
        data: { user: user_data(user) },
        message: 'メールアドレスが確認されました'
      )
    else
      render_error(
        errors: format_validation_errors(user.errors),
        message: 'メールアドレスの確認に失敗しました',
        status: :unprocessable_entity
      )
    end
  end

  # POST /api/auth/password
  def send_reset_password_instructions
    user = User.find_by(email: params[:email])

    if user
      user.send_reset_password_instructions
      render_success(message: 'パスワードリセットメールを送信しました')
    else
      render_error(
        errors: [{ field: 'email', message: 'メールアドレスが見つかりません' }],
        message: 'ユーザーが見つかりません',
        status: :not_found
      )
    end
  end

  # PUT /api/auth/password
  def reset_password
    user = User.reset_password_by_token(password_reset_params)

    if user.errors.empty?
      render_success(
        data: {
          user: user_data(user),
          token: jwt_token_for(user)
        },
        message: 'パスワードが更新されました'
      )
    else
      render_error(
        errors: format_validation_errors(user.errors),
        message: 'パスワードの更新に失敗しました',
        status: :unprocessable_entity
      )
    end
  end

  # PUT /api/auth/password/change
  def change_password
    if current_user.valid_password?(params[:current_password])
      if current_user.update(password: params[:password], password_confirmation: params[:password_confirmation])
        render_success(
          data: { user: user_data(current_user) },
          message: 'パスワードが変更されました'
        )
      else
        render_error(
          errors: format_validation_errors(current_user.errors),
          message: 'パスワードの変更に失敗しました',
          status: :unprocessable_entity
        )
      end
    else
      render_error(
        errors: [{ field: 'current_password', message: '現在のパスワードが正しくありません' }],
        message: 'パスワードの変更に失敗しました',
        status: :unauthorized
      )
    end
  end

  private

  def user_params
    params.require(:user).permit(:email, :password, :password_confirmation)
  end

  def password_reset_params
    params.permit(:reset_password_token, :password, :password_confirmation)
  end

  def user_data(user)
    {
      id: user.id,
      email: user.email,
      confirmed: user.confirmed?,
      created_at: user.created_at,
      updated_at: user.updated_at
    }
  end

  def jwt_token_for(user)
    payload = {
      sub: user.id,
      exp: 24.hours.from_now.to_i,
      iat: Time.current.to_i
    }
    JWT.encode(payload, jwt_secret, 'HS256')
  end

  def jwt_secret
    ENV['DEVISE_JWT_SECRET_KEY'] || Rails.application.secret_key_base
  end

  def render_success(data: nil, message: '', status: :ok)
    response = { success: true }
    response[:data] = data if data
    response[:message] = message if message.present?
    render json: response, status: status
  end

  def render_error(errors: [], message: '', status: :bad_request)
    render json: {
      success: false,
      errors: errors,
      message: message
    }, status: status
  end

  def format_validation_errors(errors)
    errors.map do |error|
      {
        field: error.attribute.to_s,
        message: error.message
      }
    end
  end
end
