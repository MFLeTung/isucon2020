class Post < ActiveRecord::Base
  belongs_to :user
  has_many :comment

  def comment_count
    self.comments.
  end
end
