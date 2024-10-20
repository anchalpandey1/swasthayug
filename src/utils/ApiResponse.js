class ApiResponse {
    constructor(
        statusCode,
        data = null,
        modelName = "data",
        message = "Success",
        accessToken = null,
        refreshToken = null
    ) {
        this.status = statusCode < 400;
        this.statusCode = statusCode;
        this.message = message;
        if (
            data !== null &&
            data !== undefined &&
            (typeof data === "object" ? Object.keys(data).length > 0 : true)
        ) {
            this[modelName] = data;
        }
        if (accessToken) {
            this.accessToken = accessToken;
        }
        if (refreshToken) {
            this.refreshToken = refreshToken;
        }
    }
}

export { ApiResponse };
