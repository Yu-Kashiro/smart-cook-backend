class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  def jwt_payload
    { sub: id, exp: 24.hours.from_now.to_i }
  end

  def update_jti
    self.jti = SecureRandom.uuid if has_attribute?(:jti)
    save
  end

  # JWT revocation strategy methods
  def self.jwt_revoked?(payload, user)
    user.jti != payload["jti"] if user&.respond_to?(:jti)
  end

  def self.revoke_jwt(payload, user)
    user&.update_jti if user&.respond_to?(:update_jti)
  end

  # Manual confirmation methods for API
  def confirmed?
    confirmed_at.present?
  end

  def confirm!
    self.confirmed_at = Time.current
    save(validate: false)
  end
end
