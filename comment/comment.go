package comment

// Comment represents a "post" (top-level comment) or a comment replying to
// another comment (therefore it's child).
type Comment struct {
  // Id is the ID of this comment. Must be non-zero.
  Id uint64 `json:"id"`
  // ParentId is the ID of this comment's parent comment, if applicable.
  // 0 means it's a "post" (top-level comment).
  ParentId uint64 `json:"parentId"`
  // UserId is the ID of the user who wrote this.
  UserId uint64 `json:"userId"`
  // Username is the username of the user who wrote this.
  Username string `json:"username"`
  // Content is the content of the comment.
  Content string `json:"content"`
  // Timestamp is the timestamp of the comment.
  Timestamp uint64 `json:"timestamp"`
  // NumChildren is the number of direct replies (children) to the comment
  NumChildren uint64 `json:"-"`
}
