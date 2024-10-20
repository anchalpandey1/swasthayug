class ApiError {
    constructor(statusCode, data, message = "Failed") {
        this.status = statusCode < 400;
        this.statusCode = statusCode;
        this.message = message;
    }
}

export { ApiError };
