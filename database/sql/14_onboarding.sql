/*
  14_onboarding.sql
  Persistencia del alta de cuenta, perfil, giro del comercio y solicitudes de
  métodos de cobro. No contiene CLABEs, llaves ni secretos del proveedor.
*/
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH(N'biz.ComercioMetodosPago', N'Solicitado') IS NULL
  ALTER TABLE biz.ComercioMetodosPago ADD Solicitado BIT NOT NULL CONSTRAINT DF_biz_MetodosPago_Solicitado DEFAULT 0;
GO
IF COL_LENGTH(N'biz.ComercioMetodosPago', N'EstadoConfiguracion') IS NULL
  ALTER TABLE biz.ComercioMetodosPago ADD EstadoConfiguracion NVARCHAR(24) NOT NULL CONSTRAINT DF_biz_MetodosPago_Estado DEFAULT N'PENDIENTE';
GO
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name=N'CK_biz_MetodosPago_EstadoConfiguracion')
  ALTER TABLE biz.ComercioMetodosPago ADD CONSTRAINT CK_biz_MetodosPago_EstadoConfiguracion CHECK (EstadoConfiguracion IN (N'DISPONIBLE',N'PENDIENTE',N'REQUIERE_PEY',N'PROXIMAMENTE'));
GO
IF NOT EXISTS (SELECT 1 FROM lkp.MetodosPago WHERE Codigo=N'PEY_CODI')
  INSERT lkp.MetodosPago (MetodoPagoId,Codigo,Nombre,RequiereAntifraude)
  VALUES ((SELECT ISNULL(MAX(MetodoPagoId),0)+1 FROM lkp.MetodosPago),N'PEY_CODI',N'CoDi QR con Pey',0);
GO
IF NOT EXISTS (SELECT 1 FROM lkp.MetodosPago WHERE Codigo=N'WALLETS')
  INSERT lkp.MetodosPago (MetodoPagoId,Codigo,Nombre,RequiereAntifraude)
  VALUES ((SELECT ISNULL(MAX(MetodoPagoId),0)+1 FROM lkp.MetodosPago),N'WALLETS',N'Wallets',0);
GO

CREATE OR ALTER VIEW app.ColoniasPublicas AS
  SELECT ColoniaId, Nombre, Ciudad FROM lkp.Colonias;
GO
CREATE OR ALTER VIEW app.CategoriasPublicas AS
  SELECT CategoriaId, Nombre FROM lkp.Categorias WHERE EstaActivo=1;
GO

CREATE OR ALTER PROCEDURE app.sp_RegistrarUsuario
  @Correo NVARCHAR(256)=NULL,
  @Telefono NVARCHAR(20)=NULL,
  @HashContrasena VARBINARY(256),
  @SalContrasena VARBINARY(64),
  @TipoUso TINYINT,
  @NombreMostrar NVARCHAR(100),
  @ColoniaId INT=NULL,
  @Biografia NVARCHAR(300)=NULL,
  @UsuarioId UNIQUEIDENTIFIER OUTPUT
AS
BEGIN
  SET NOCOUNT ON; SET XACT_ABORT ON;
  IF @TipoUso NOT IN (1,2,3) THROW 51401,'Tipo de cuenta inválido.',1;
  BEGIN TRANSACTION;
  BEGIN TRY
    DECLARE @NuevosUsuarios TABLE (UsuarioId UNIQUEIDENTIFIER);
    INSERT ident.Usuarios (Correo,Telefono,HashContrasena,SalContrasena,TipoUso)
      OUTPUT inserted.UsuarioId INTO @NuevosUsuarios
      VALUES (@Correo,@Telefono,@HashContrasena,@SalContrasena,@TipoUso);
    SELECT @UsuarioId=UsuarioId FROM @NuevosUsuarios;
    INSERT ident.Perfiles (UsuarioId,NombreMostrar,Biografia,ColoniaId)
      VALUES (@UsuarioId,@NombreMostrar,@Biografia,@ColoniaId);
    INSERT ident.UsuarioRoles (UsuarioId,RolId)
      SELECT @UsuarioId,RolId FROM lkp.Roles
      WHERE (@TipoUso IN (1,3) AND Nombre=N'Comprador') OR (@TipoUso IN (2,3) AND Nombre=N'Comercio');
    COMMIT TRANSACTION;
  END TRY
  BEGIN CATCH
    IF @@TRANCOUNT>0 ROLLBACK TRANSACTION;
    THROW;
  END CATCH
END;
GO

CREATE OR ALTER PROCEDURE app.sp_CrearComercioPropio
  @UsuarioId UNIQUEIDENTIFIER,
  @NombreNegocio NVARCHAR(150),
  @Descripcion NVARCHAR(500)=NULL,
  @ColoniaId INT=NULL,
  @CategoriaId INT=NULL,
  @ComercioId UNIQUEIDENTIFIER OUTPUT
AS
BEGIN
  SET NOCOUNT ON; SET XACT_ABORT ON;
  IF NOT EXISTS (SELECT 1 FROM ident.UsuarioRoles ur JOIN lkp.Roles r ON r.RolId=ur.RolId WHERE ur.UsuarioId=@UsuarioId AND r.Nombre=N'Comercio')
    THROW 50101,'El usuario no tiene rol de comercio.',1;
  IF EXISTS (SELECT 1 FROM biz.Comercios WHERE UsuarioPropietarioId=@UsuarioId)
    THROW 50102,'El usuario ya tiene un comercio.',1;
  BEGIN TRANSACTION;
  BEGIN TRY
    SET @ComercioId=NEWID();
    INSERT biz.Comercios (ComercioId,UsuarioPropietarioId,NombreNegocio,Descripcion,ColoniaId)
      VALUES (@ComercioId,@UsuarioId,@NombreNegocio,@Descripcion,@ColoniaId);
    IF @CategoriaId IS NOT NULL INSERT biz.ComercioCategorias (ComercioId,CategoriaId) VALUES (@ComercioId,@CategoriaId);
    COMMIT TRANSACTION;
  END TRY
  BEGIN CATCH
    IF @@TRANCOUNT>0 ROLLBACK TRANSACTION;
    THROW;
  END CATCH
END;
GO

CREATE OR ALTER PROCEDURE app.sp_GuardarMetodosPagoPropios
  @UsuarioId UNIQUEIDENTIFIER,
  @MetodosJson NVARCHAR(MAX)
AS
BEGIN
  SET NOCOUNT ON; SET XACT_ABORT ON;
  DECLARE @ComercioId UNIQUEIDENTIFIER=(SELECT TOP(1) ComercioId FROM biz.Comercios WHERE UsuarioPropietarioId=@UsuarioId AND EstaActivo=1);
  IF @ComercioId IS NULL THROW 51402,'Primero crea el perfil del negocio.',1;
  IF ISJSON(@MetodosJson)<>1 THROW 51403,'Lista de métodos inválida.',1;
  DECLARE @Metodos TABLE (Codigo NVARCHAR(20) PRIMARY KEY, Solicitado BIT NOT NULL);
  INSERT @Metodos (Codigo,Solicitado)
    SELECT Codigo,Solicitado FROM OPENJSON(@MetodosJson) WITH (Codigo NVARCHAR(20) '$.code',Solicitado BIT '$.selected');
  IF EXISTS (SELECT 1 FROM @Metodos m LEFT JOIN lkp.MetodosPago p ON p.Codigo=m.Codigo WHERE p.MetodoPagoId IS NULL)
    THROW 51404,'Método de pago desconocido.',1;
  BEGIN TRANSACTION;
  MERGE biz.ComercioMetodosPago AS target
  USING (SELECT p.MetodoPagoId,p.Codigo,m.Solicitado FROM @Metodos m JOIN lkp.MetodosPago p ON p.Codigo=m.Codigo) AS source
    ON target.ComercioId=@ComercioId AND target.MetodoPagoId=source.MetodoPagoId
  WHEN MATCHED THEN UPDATE SET
    target.Solicitado=source.Solicitado,
    target.EstaHabilitado=CASE WHEN source.Codigo=N'EFECTIVO' AND source.Solicitado=1 THEN 1 ELSE 0 END,
    target.EstadoConfiguracion=CASE
      WHEN source.Solicitado=0 THEN N'PENDIENTE'
      WHEN source.Codigo=N'EFECTIVO' THEN N'DISPONIBLE'
      WHEN source.Codigo=N'PEY_CODI' THEN N'REQUIERE_PEY'
      WHEN source.Codigo=N'NFC' THEN N'PROXIMAMENTE'
      ELSE N'PENDIENTE' END
  WHEN NOT MATCHED THEN INSERT (ComercioId,MetodoPagoId,EstaHabilitado,Solicitado,EstadoConfiguracion)
    VALUES (@ComercioId,source.MetodoPagoId,CASE WHEN source.Codigo=N'EFECTIVO' AND source.Solicitado=1 THEN 1 ELSE 0 END,source.Solicitado,
      CASE WHEN source.Solicitado=0 THEN N'PENDIENTE' WHEN source.Codigo=N'EFECTIVO' THEN N'DISPONIBLE' WHEN source.Codigo=N'PEY_CODI' THEN N'REQUIERE_PEY' WHEN source.Codigo=N'NFC' THEN N'PROXIMAMENTE' ELSE N'PENDIENTE' END);
  COMMIT TRANSACTION;
  SELECT p.Codigo,m.EstaHabilitado,m.Solicitado,m.EstadoConfiguracion
    FROM biz.ComercioMetodosPago m JOIN lkp.MetodosPago p ON p.MetodoPagoId=m.MetodoPagoId
    WHERE m.ComercioId=@ComercioId ORDER BY p.MetodoPagoId;
END;
GO

CREATE OR ALTER PROCEDURE app.sp_ObtenerMetodosPagoPropios @UsuarioId UNIQUEIDENTIFIER
AS
BEGIN
  SET NOCOUNT ON;
  SELECT p.Codigo,p.Nombre,m.EstaHabilitado,m.Solicitado,m.EstadoConfiguracion
    FROM biz.ComercioMetodosPago m JOIN lkp.MetodosPago p ON p.MetodoPagoId=m.MetodoPagoId
    JOIN biz.Comercios c ON c.ComercioId=m.ComercioId
    WHERE c.UsuarioPropietarioId=@UsuarioId ORDER BY p.MetodoPagoId;
END;
GO

GRANT SELECT ON app.ColoniasPublicas TO role_app_api;
GRANT SELECT ON app.CategoriasPublicas TO role_app_api;
GRANT EXECUTE ON OBJECT::app.sp_RegistrarUsuario TO role_app_api;
GRANT EXECUTE ON OBJECT::app.sp_CrearComercioPropio TO role_app_api;
GRANT EXECUTE ON OBJECT::app.sp_GuardarMetodosPagoPropios TO role_app_api;
GRANT EXECUTE ON OBJECT::app.sp_ObtenerMetodosPagoPropios TO role_app_api;
GO
