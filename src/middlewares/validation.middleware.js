export const validateRequestBody = (req, res, next) => {
    console.log("Request Body:", req.body); // Debugging line

    const fields = req.body;

    // if (!fields || Object.keys(fields).length === 0) {
    //     return res.status(400).json({
    //         status: 'error',
    //         message: 'Request body is empty.'
    //     });
    // }

    for (const [key, value] of Object.entries(fields)) {
        if (
            value === undefined ||
            value === null ||
            value === "" ||
            (typeof value === "string" && !value.trim())
        ) {
            return res.status(400).json({
                status: "error",
                message: `Field "${key}" is required and cannot be empty or just whitespace.`,
            });
        }
    }

    next();
};
