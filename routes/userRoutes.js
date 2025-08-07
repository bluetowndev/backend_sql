import { Router } from "express";
import { createUser, distanceTravelled, getAttendanceRecords, getProfile, loginUser, mapRecord, saveAttendance, verifyEmail } from "../controller/userController.js";
import { authenticate } from "../middleware/auth.js";

const router= Router();

router.post("/signup", createUser);
router.post("/login", loginUser);
router.get("/verifyEmail", verifyEmail)
router.get("/me", getProfile )
router.post("/attendance", saveAttendance)
router.get("/viewAttendance", getAttendanceRecords)
router.post("/calculateDistance", distanceTravelled)
router.get("/mapAttendance/:date", authenticate, mapRecord)

export default router;