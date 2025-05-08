import { Router } from "express";
import { createUser, getAttendanceRecords, getProfile, loginUser, saveAttendance, verifyEmail } from "../controller/userController.js";

const router= Router();

router.post("/signup", createUser);
router.post("/login", loginUser);
router.get("/verifyEmail", verifyEmail)
router.get("/me", getProfile )
router.post("/attendance", saveAttendance)
router.get("/viewAttendance", getAttendanceRecords)

export default router;