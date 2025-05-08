import { Router } from "express";
import userRoutes from "./userRoutes.js"

const router= Router();

router.use("/api/v1/user", userRoutes)

export default router;