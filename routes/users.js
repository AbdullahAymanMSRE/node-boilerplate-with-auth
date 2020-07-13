const mongoose = require("mongoose");
const router = require("express").Router();
const User = mongoose.model("User");
const passport = require("passport");
const { genPassword, issueJWT, validPassword } = require("../lib/utils");

router.post("/login", function (req, res, next) {
  User.findOne({ username: req.body.username })
    .then((user) => {
      if (!user) {
        return res
          .status(401)
          .json({ success: false, msg: "Invalid Username Or Password" });
      }

      const isValid = validPassword(req.body.password, user.hash, user.salt);

      if (!isValid) {
        return res
          .status(401)
          .json({ success: false, msg: "Invalid Username Or Password" });
      }

      res.json({ success: true, user, ...issueJWT(user) });
    })
    .catch((err) => next(err));
});

router.post("/register", (req, res, next) => {
  const { salt, hash } = genPassword(req.body.password);

  const newUser = new User({ username: req.body.username, hash, salt });

  newUser
    .save()
    .then((user) => {
      res.json({ success: true, user, ...issueJWT(user) });
    })
    .catch((err) => next(err));
});

module.exports = router;
