const asyncHandler = (requestHandler) => {
  //request Handler
  return (req, res, next) => {
    Promise.resolve(requestHandler(req, res, next)).catch((err) => next(err));
  };
};

export { asyncHandler }
