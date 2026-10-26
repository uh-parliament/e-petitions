class CreateParliamentStaffCredentials < ActiveRecord::Migration[8.0]
  def change
    create_table :parliament_staff_credentials do |t|
      t.references :admin_user, null: false, foreign_key: true, index: { unique: true }
      t.string :password_digest
      t.text :totp_ciphertext
      t.string :enrolment_digest
      t.datetime :enrolment_expires_at
      t.integer :failed_attempts, null: false, default: 0
      t.datetime :locked_until
      t.bigint :last_totp_step
      t.timestamps
    end
    add_index :parliament_staff_credentials, :enrolment_digest, unique: true
  end
end
