package zerossl

type retryStateCtxKey struct{}

// AttemptsCtxKey is the context key for the value
// that holds the attempt counter. The value counts
// how many times the operation has been attempted.
// A value of 0 means first attempt.
var AttemptsCtxKey retryStateCtxKey
