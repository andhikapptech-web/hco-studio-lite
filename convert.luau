local fs = require("@lune/fs")
local process = require("@lune/process")
local roblox = require("@lune/roblox")

local inputPath = process.args[1]
local outputPath = process.args[2]
local mode = process.args[3] or "workspace"
local modelName = process.args[4] or "StudioLiteAsset"
local stripMedia = (process.args[5] == "true")

local function shouldSkip(inst)
	if inst.ClassName == "Camera" or inst.ClassName == "Terrain" then
		return true
	end
	if stripMedia then
		if inst.ClassName == "Sound" or inst.ClassName == "SoundGroup" or inst.ClassName == "VideoFrame" then
			return true
		end
	end
	return false
end

local function cleanDescendants(root)
	if not stripMedia then return end
	local toRemove = {}
	for _, desc in root:GetDescendants() do
		if desc.ClassName == "Sound" or desc.ClassName == "SoundGroup" or desc.ClassName == "VideoFrame" then
			table.insert(toRemove, desc)
		end
	end
	for _, item in toRemove do
		item.Parent = nil
	end
end

local rawContent = fs.readFile(inputPath)
local lowerPath = string.lower(inputPath)
local isPlace = string.sub(lowerPath, -5) == ".rbxl" or string.sub(lowerPath, -6) == ".rbxlx"

if isPlace then
	local game = roblox.deserializePlace(rawContent)
	local rootModel = roblox.Instance.new("Model")
	rootModel.Name = modelName

	if mode == "workspace" then
		local ws = game:GetService("Workspace")
		for _, child in ws:GetChildren() do
			if not shouldSkip(child) then
				child.Parent = rootModel
			end
		end
	else
		local services = {
			"Workspace", "Lighting", "ReplicatedFirst", "ReplicatedStorage",
			"ServerScriptService", "ServerStorage", "StarterGui", "StarterPack",
			"StarterPlayer", "SoundService", "Teams"
		}
		for _, sName in services do
			if stripMedia and sName == "SoundService" then continue end
			local ok, service = pcall(function() return game:GetService(sName) end)
			if ok and service then
				local valid = {}
				for _, child in service:GetChildren() do
					if not shouldSkip(child) then table.insert(valid, child) end
				end
				if #valid > 0 then
					local folder = roblox.Instance.new("Folder")
					folder.Name = sName
					folder.Parent = rootModel
					for _, child in valid do child.Parent = folder end
				end
			end
		end
	end

	cleanDescendants(rootModel)
	fs.writeFile(outputPath, roblox.serializeModel({ rootModel }))
else
	local instances = roblox.deserializeModel(rawContent)
	local filtered = {}
	for _, inst in instances do
		if not shouldSkip(inst) then
			cleanDescendants(inst)
			table.insert(filtered, inst)
		end
	end
	fs.writeFile(outputPath, roblox.serializeModel(filtered))
end